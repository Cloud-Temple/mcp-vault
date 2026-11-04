"""Unresolved catalog identities must never enter a restore fingerprint."""

from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "kind,index", [("schema", 2), ("relations", 3), ("functions", 3), ("defaults", 3)]
)
@pytest.mark.parametrize("missing", [0, 2])
def test_acl_missing_role_refuses(monkeypatch, kind, index, missing):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import standalone_pg as api

    grant = ["owner", "ROLE", "neighbor", "SELECT", False]
    grant[missing] = None

    class Catalog:
        def execute(self, query, params):
            self.rows = []
            if f"structure:{kind} */" in query:
                row = ["object"] * index + [[grant]]
                self.rows = [row]
            return self

        def fetchall(self):
            return self.rows

    with pytest.raises(ValueError, match="non résolue"):
        api.structure_signature(Catalog(), "owner")


@pytest.mark.parametrize(
    "kind,index", [("schema", 1), ("relations", 2), ("functions", 2), ("defaults", 0)]
)
def test_acl_missing_owner_even_empty_refuses(monkeypatch, kind, index):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "scripts"))
    import standalone_pg as api

    class Catalog:
        def execute(self, query, params):
            self.rows = []
            if f"structure:{kind} */" in query:
                row = ["object", "object", "object", []]
                if kind == "schema":
                    row = ["vault_metadata", "owner", []]
                row[index] = None
                self.rows = [row]
            return self

        def fetchall(self):
            return self.rows

    with pytest.raises(ValueError, match="Owner PostgreSQL non résolu"):
        api.structure_signature(Catalog(), "owner")
