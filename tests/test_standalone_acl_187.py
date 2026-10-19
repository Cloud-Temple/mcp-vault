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
            name: i + 10 for i, name in enumerate([*self.roles.values(), "infra_a"])
        }
        self.owner = self.oids["a_owner"]
        self.user, self.version = "infra_a", 160000
        self.allow, self.sessions, self.effects, self.rows = True, [], [], []
        self.acl = {(self.owner, oid, "CONNECT", False) for oid in self.oids.values()}
        self.neighbor = {"owner": "b_owner", "acl": ["untouched"], "allow": True}

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
        elif text.startswith("SELECT rolname,rolcanlogin"):
            self.rows = [
                (name, name != "a_owner", False, False, False, False, False, False)
                for name in self.roles.values()
            ]
        elif "FROM pg_auth_members WHERE member=ANY" in text:
            self.rows = [
                (self.roles[k], "a_owner", False, False, True)
                for k in ("provisioner", "backup", "restore")
            ]
            self.rows += [
                ("infra_a", name, True, False, True) for name in self.roles.values()
            ]
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
