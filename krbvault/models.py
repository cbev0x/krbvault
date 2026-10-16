"""Dataclasses and enums for the krbvault object model.

The join key across the whole store is the *identity* (principal@REALM).
Both credentials and tickets are authentication material hanging off it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class CredType(str, Enum):
    PASSWORD = "password"
    NT = "nt"            # NTLM hash (hex)
    AES256 = "aes256"    # Kerberos AES256 key (hex)
    AES128 = "aes128"    # Kerberos AES128 key (hex)
    RC4 = "rc4"          # RC4/NTLM key (hex) — alias of NT in practice
    DES = "des"          # legacy DES key (hex)
    AESKEY = "aeskey"    # generic Kerberos key, etype unknown (hex)
    PFX = "pfx"          # PKINIT cert + private key (binary PFX/PKCS#12)


HEX_CRED_TYPES = {CredType.NT, CredType.AES256, CredType.AES128,
                  CredType.RC4, CredType.DES, CredType.AESKEY}


class IdentityType(str, Enum):
    USER = "user"
    COMPUTER = "computer"
    SERVICE = "service"
    KRBTGT = "krbtgt"
    UNKNOWN = "unknown"


class TicketKind(str, Enum):
    TGT = "TGT"
    TGS = "TGS"


@dataclass
class Identity:
    id: Optional[int]
    principal: str
    realm: str
    itype: str = IdentityType.UNKNOWN.value
    sid: Optional[str] = None
    privileged: bool = False
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    created_at: Optional[str] = None

    @property
    def upn(self) -> str:
        return f"{self.principal}@{self.realm}"


@dataclass
class Credential:
    id: Optional[int]
    identity_id: int
    ctype: str
    value: bytes           # plaintext here; the store seals it at rest
    source: Optional[str] = None
    obtained_at: Optional[str] = None
    created_at: Optional[str] = None


@dataclass
class Ticket:
    id: Optional[int]
    identity_id: int
    kind: str              # TicketKind value
    client: str = ""
    client_realm: str = ""
    server: str = ""       # SPN
    server_realm: str = ""
    flags: List[str] = field(default_factory=list)
    key_etype: Optional[int] = None
    etype_name: Optional[str] = None
    auth_time: Optional[str] = None     # ISO 8601 UTC
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    renew_till: Optional[str] = None
    blob: bytes = b""      # plaintext single-credential ccache; sealed at rest
    source: Optional[str] = None
    created_at: Optional[str] = None
