"""Strict SQL transport model: actual helpers, ACL state and grantor semantics.

This intentionally does not claim PostgreSQL accepts the generated statements.
The native server run must still prove privileges, signals, dump and restore.
"""

import re
from pathlib import Path

import pytest


@pytest.fixture
def pg(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import standalone_pg_sql

    return standalone_pg_sql


class Catalog:
    def __init__(self):
        self.roles = {
            kind: "a_" + kind
            for kind in (
                "owner",
                "app",
                "provisioner",
                "maintenance",
                "backup",
                "restore",
            )
        }
        self.oids = {
            name: i + 16384 for i, name in enumerate([*self.roles.values(), "infra_a"])
        }
        self.owner = self.oids["a_owner"]
        self.user, self.version = "infra_a", 160000
        self.allow, self.sessions, self.effects, self.rows = True, [], [], []
        self.acl = {(self.owner, oid, "CONNECT", False) for oid in self.oids.values()}
        self.neighbor = {"owner": "b_owner", "acl": ["untouched"], "allow": True}
        # PG16 initdb bootstrap identity, distinct from all freshly created roles.
        self.bootstrap = (10, "renamed_engine_bootstrap", True)
        self.memberships = None
        self.attributes = None
        self.effective_set = set(self.roles.values())
        self.login_user = "infra_a"
        self.application_set = False

    def membership_rows(self):
        if self.memberships is not None:
            return self.memberships
        infra = self.oids["infra_a"]
        bootstrap, bootstrap_name, _ = self.bootstrap
        rows = [
            (
                self.oids[self.roles[k]],
                self.roles[k],
                self.oids[self.roles["owner"]],
                self.roles["owner"],
                infra,
                "infra_a",
                False,
                False,
                True,
            )
            for k in ("provisioner", "backup", "restore")
        ]
        for name in self.roles.values():
            # Two independent pg_auth_members rows, never a merged grant.
            rows += [
                (
                    infra,
                    "infra_a",
                    self.oids[name],
                    name,
                    bootstrap,
                    bootstrap_name,
                    True,
                    False,
                    False,
                ),
                (
                    infra,
                    "infra_a",
                    self.oids[name],
                    name,
                    infra,
                    "infra_a",
                    False,
                    False,
                    True,
                ),
            ]
        return rows

    def execute(self, statement, params=None):
        text = statement if isinstance(statement, str) else statement.as_string()
        self.rows = []
        if text == "SHOW server_version_num":
            self.rows = [(self.version,)]
        elif text.startswith("SELECT rolsuper,rolcreatedb"):
            self.rows = [(False, True, True, False, False)]
        elif text.startswith("SELECT rolname,oid"):
            self.rows = [
                (name, oid) for name, oid in self.oids.items() if name in params[0]
            ]
        elif text.startswith("SELECT session_user,current_user"):
            self.rows = [(self.login_user, self.user)]
        elif "standalone:bootstrap-grantor" in text:
            self.rows = [self.bootstrap]
        elif text.startswith("SELECT pg_has_role(session_user"):
            self.rows = [(params[0] in self.effective_set,)]
        elif text.startswith("SELECT pg_has_role(%s,%s,'SET')"):
            self.rows = [(self.application_set,)]
        elif text.startswith("SELECT rolname,rolcanlogin"):
            rows = (
                self.attributes
                if self.attributes is not None
                else [
                    (
                        name,
                        name != self.roles["owner"],
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                    )
                    for name in self.roles.values()
                ]
                + [("infra_a", True, False, False, True, True, False, False)]
            )
            self.rows = [row for row in rows if row[0] in params[0]]
        elif "pg_auth_members" in text:
            rows = self.membership_rows()
            self.rows = (
                rows if "m.grantor" in text else [(r[1], r[3], *r[6:]) for r in rows]
            )
        elif text.startswith("SELECT oid,datdba"):
            assert params == ("source_a",)
            self.rows = [(100, self.owner, self.allow)]
        elif "aclexplode(COALESCE(d.datacl" in text:
            assert params == ("source_a",)
            self.rows = sorted(self.acl)
        elif text.startswith("SELECT pid,usesysid"):
            assert params == ("source_a",)
            self.rows = list(self.sessions)
        elif text.startswith("SELECT has_database_privilege"):
            self.rows = [
                (
                    any(
                        grantee == self.oids[params[0]] and privilege == "CONNECT"
                        for _, grantee, privilege, _ in self.acl
                    ),
                )
            ]
        elif text.startswith("SET ROLE"):
            self.user = re.findall('"([^"]+)"', text)[0]
        elif text == "RESET ROLE":
            self.user = "infra_a"
        elif text.startswith("REVOKE CONNECT"):
            assert '"source_a"' in text
            role = re.findall('"([^"]+)"', text)
            grantee = self.oids[role[1]] if len(role) > 1 else 0
            grantor = self.oids[self.user]
            self.acl = {
                a
                for a in self.acl
                if not (a[0] == grantor and a[1] == grantee and a[2] == "CONNECT")
            }
            self.effects.append((text, self.user))
        elif text.startswith("ALTER DATABASE"):
            assert text == 'ALTER DATABASE "source_a" ALLOW_CONNECTIONS false'
            assert self.user == "a_owner"
            self.allow = False
            self.effects.append((text, self.user))
        elif text.startswith("SELECT pg_terminate_backend"):
            pid, database = params
            assert database == "source_a"
            eligible = [s for s in self.sessions if s[0] == pid and s[2] == self.user]
            self.rows = [(bool(eligible),)]
            self.sessions = [s for s in self.sessions if s not in eligible]
            self.effects.append((text, self.user))
        else:
            raise AssertionError("Unmodelled SQL: " + text)
        return self

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def test_freeze_retains_backup_then_seal_removes_it_same_grantor(pg):
    conn = Catalog()
    conn.sessions = [(1, conn.oids["a_app"], "a_app")]
    before, frozen = pg.freeze(conn, "source_a", conn.roles, "infra_a")
    assert frozen["sessions"] == [] and frozen["allow_connections"]
    assert before["sessions"] == []
    assert {row[1] for row in frozen["acl"]} == {
        conn.oids[k] for k in ("a_owner", "a_backup", "infra_a")
    }
    _, sealed = pg.freeze(conn, "source_a", conn.roles, "infra_a", sealed=True)
    assert sealed["allow_connections"] is False
    assert sealed["acl"] == [[conn.owner, conn.owner, "CONNECT", False]]
    assert all(
        user == "a_owner"
        for statement, user in conn.effects
        if statement.startswith("REVOKE")
    )
    assert conn.neighbor == {"owner": "b_owner", "acl": ["untouched"], "allow": True}


def test_pg16_dual_grantors_are_accepted(pg):
    conn = Catalog()
    assert pg.domain_roles(conn, conn.roles, "infra_a") == conn.oids
    assert len(conn.membership_rows()) == 15


@pytest.mark.parametrize(
    "change",
    [
        "missing-bootstrap",
        "missing-self",
        "foreign-grantor",
        "fake-grantor-name",
        "foreign-parent",
        "foreign-member",
        "app-owner",
        "self-inherit",
        "self-admin",
        "self-no-set",
        "invalid-flag",
        "invalid-oid",
        "duplicate",
        "missing-effective-set",
        "app-effective-set",
        "wrong-login",
        "wrong-current-role",
        "privileged-app",
        "invalid-role-flag",
        "fake-bootstrap-oid",
        "not-super-bootstrap",
        "invalid-bootstrap-flag",
    ],
)
def test_pg16_graph_rejects_noncanonical_or_ineffective_authority(pg, change):
    conn = Catalog()
    rows = conn.membership_rows()
    row = list(rows[-1])  # infra self-grant to the last role A
    if change == "missing-bootstrap":
        rows.pop(-2)
    elif change == "missing-self":
        rows.pop()
    elif change == "foreign-grantor":
        row[4:6] = [54321, "foreign_superuser"]
        rows[-1] = tuple(row)
    elif change == "fake-grantor-name":
        row[5] = "not_the_catalog_infra"
        rows[-1] = tuple(row)
    elif change == "foreign-parent":
        row[2:4] = [54321, "neighbor_b_owner"]
        rows[-1] = tuple(row)
    elif change == "foreign-member":
        row[0:2] = [54321, "neighbor_b_app"]
        rows.append(tuple(row))
    elif change == "app-owner":
        rows.append(
            (
                conn.oids[conn.roles["app"]],
                conn.roles["app"],
                conn.owner,
                conn.roles["owner"],
                conn.oids["infra_a"],
                "infra_a",
                False,
                False,
                True,
            )
        )
    elif change in {
        "self-inherit",
        "self-admin",
        "self-no-set",
        "invalid-flag",
        "invalid-oid",
    }:
        index, value = {
            "self-inherit": (7, True),
            "self-admin": (6, True),
            "self-no-set": (8, False),
            "invalid-flag": (8, 1),
            "invalid-oid": (0, True),
        }[change]
        row[index] = value
        rows[-1] = tuple(row)
    elif change == "duplicate":
        rows.append(rows[-1])
    elif change == "missing-effective-set":
        conn.effective_set.remove(conn.roles["maintenance"])
    elif change == "app-effective-set":
        conn.application_set = True
    elif change == "wrong-login":
        conn.login_user = "other_infra"
    elif change == "wrong-current-role":
        conn.user = conn.roles["owner"]
    elif change in {"privileged-app", "invalid-role-flag"}:
        conn.attributes = [
            (
                name,
                name != conn.roles["owner"],
                False,
                name == conn.roles["app"] if change == "privileged-app" else 0,
                False,
                False,
                False,
                False,
            )
            for name in conn.roles.values()
        ]
        conn.attributes.append(
            ("infra_a", True, False, False, True, True, False, False)
        )
    elif change == "fake-bootstrap-oid":
        conn.bootstrap = (42, conn.bootstrap[1], True)
    elif change == "not-super-bootstrap":
        conn.bootstrap = (10, conn.bootstrap[1], False)
    else:
        conn.bootstrap = (10, conn.bootstrap[1], 1)
    conn.memberships = rows
    with pytest.raises(ValueError):
        pg.domain_roles(conn, conn.roles, "infra_a")
    assert conn.effects == []


def test_other_grantor_cannot_silently_survive_revoke(pg):
    conn = Catalog()
    conn.acl.add((9876, conn.oids["a_app"], "CONNECT", False))
    with pytest.raises(ValueError, match="grantor"):
        pg.freeze(conn, "source_a", conn.roles, "infra_a")
    assert (9876, conn.oids["a_app"], "CONNECT", False) in conn.acl
    assert conn.allow  # Pas de seal après un freeze non confirmé.


def test_neighbor_owner_refused_before_any_effect(pg):
    conn = Catalog()
    conn.owner = 999
    with pytest.raises(ValueError, match="voisine"):
        pg.freeze(conn, "source_a", conn.roles, "infra_a")
    assert conn.effects == []


def test_unknown_session_never_signaled(pg):
    conn = Catalog()
    conn.sessions = [(5, 999, "b_app")]
    with pytest.raises(ValueError, match="étrangère"):
        pg.freeze(conn, "source_a", conn.roles, "infra_a")
    assert not any("pg_terminate_backend" in statement for statement, _ in conn.effects)
    assert conn.sessions == [(5, 999, "b_app")]


@pytest.mark.parametrize("version", [150000, 0])
def test_server_version_is_measured_before_ddl(pg, version):
    conn = Catalog()
    conn.version = version
    with pytest.raises(ValueError, match="mesuré"):
        pg.preflight(conn)
    assert conn.effects == []


@pytest.mark.parametrize(
    "identifier", ['a";DROP DATABASE b', "B", "neighbor.b", "a b", ""]
)
def test_identifiers_refused_before_create_database(pg, identifier):
    conn = Catalog()
    with pytest.raises(ValueError):
        pg.create_database(conn, identifier, conn.roles, "infra_a", private=True)
    assert conn.effects == []
