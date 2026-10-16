# krbvault

A consolidated, encrypted store for Kerberos **tickets and credentials**,
organized by **identity**, for authorized red-team engagements.

On a large engagement your auth material sprawls: ccache files in `/tmp`, a few
`.kirbi`s, NT hashes and AES keys pasted into notes, a PFX or two. `krbvault`
keeps it all in one encrypted file per engagement, keyed on `user@REALM`, and
makes switching the *active* identity a single command.

> **Authorized use only.** This organizes material you have already obtained
> under a signed scope. If you discover a vulnerability while using it, report
> it to the vendor first.

## Why

- **One store, keyed by identity.** Credentials and tickets are just auth
  material hanging off an identity; group them by identity and domain.
- **Switch identity in one command.** `krbvault use alice@CORP.LOCAL` points
  `KRB5CCNAME` at the right ticket — no more exporting a path per command.
- **Encrypted at rest.** Ticket bytes and credential values are sealed with a
  passphrase-derived key. A copy of the file on the testing box is not a
  plaintext credential dump.
- **Ticket lifetimes at a glance.** `ls` shows which TGTs are live, expiring,
  or dead, so you don't discover a dead TGT three commands into a chain.
- **Stop translating flags by hand.** `emit` prints the exact invocation
  dialect for impacket / NetExec / Rubeus from the material you've stored.

## Install

```bash
git clone https://github.com/cbev0x/krbvault
cd krbvault
pip install -e .
```

Requires Python 3.9+. Pulls in `pynacl` (crypto), `impacket` (ccache/kirbi
parsing), and `rich` (tables).

One-time shell setup so tools read the active ticket:

```bash
krbvault env >> ~/.bashrc      # adds: export KRB5CCNAME="$HOME/.krbvault/active.ccache"
```

## Quickstart

```bash
# create a vault for this engagement (prompts for a passphrase)
krbvault -e acme init

# stay unlocked for the session (agent holds the key, like ssh-agent)
krbvault -e acme unlock --ttl 28800

# import tickets you've collected
krbvault -e acme import loot/Administrator.ccache
krbvault -e acme import loot/svc.kirbi

# stash credentials against an identity
krbvault -e acme add svc_sql@CORP.LOCAL --nt <nthash> --aes256 <key> --source dump
krbvault -e acme add web01\$@CORP.LOCAL --aes256 <key>

# see what you control, by domain, with ticket health
krbvault -e acme ls

# make a ticket active, then run your tools normally
krbvault -e acme use Administrator@CORP.LOCAL
secretsdump.py -k -no-pass CORP.LOCAL/Administrator@dc01

# or get ready-to-paste flags for a specific tool
krbvault -e acme emit svc_sql@CORP.LOCAL --for nxc --target dc01
```

The `-e/--engagement` name selects the vault file. If you `cd` into a directory
that contains a `.krbvault/` folder, that engagement is used automatically.

## Commands

| Command | What it does |
|---|---|
| `init` | Create a new vault (prompts for a passphrase). |
| `unlock [--ttl]` / `lock` | Start/stop the unlock agent so you don't retype the passphrase. |
| `status` | Vault summary: identities, counts, lock state. |
| `import <file> [--identity] [--source]` | Import a ccache or kirbi; auto-detects format, splits multi-credential caches, infers the identity. |
| `add <upn> --password/--nt/--aes256/--aes128/--rc4/--des/--pfx` | Store credential material for an identity. |
| `ls [--domain]` | Identities grouped by realm, with best-ticket health. |
| `describe <upn \| #id>` | Full detail for an identity or a specific ticket. |
| `use <upn \| #id> [--export] [--shell] [--for TOOL]` | Make a ticket the active `KRB5CCNAME`. |
| `emit <upn> --for TOOL [--target]` | Print impacket/nxc/Rubeus flags for the stored material. |
| `reveal <upn> [--ctype]` | Print a stored credential (PFX is written to a file). |
| `rm <upn \| #id>` | Delete an identity (and its material) or one ticket. |
| `passwd` | Re-wrap the vault under a new passphrase. |

### Switching modes

- **default** — `use` writes to the single active ccache the shell export
  points at. Simplest; one active identity at a time.
- **`--export`** — writes to a per-identity path and prints an
  `export KRB5CCNAME=…` line for `eval "$(krbvault use alice --export)"`, so
  several shells can hold different identities in parallel.
- **`--shell`** — drops you into a subshell scoped to that ticket; the ccache
  is cleaned up on exit.

## Security model

- **Envelope encryption.** Your passphrase is run through **Argon2id** to a key
  that wraps a random per-vault data key (DEK). Ticket bytes and credential
  values are sealed with the DEK using **XChaCha20-Poly1305**. Changing the
  passphrase re-wraps the DEK only — stored secrets are never re-encrypted.
- **What's encrypted:** the secret-bearing material — ticket blobs, passwords,
  NT/AES keys, PFX files.
- **What's *not* encrypted:** metadata — principals, SPNs, realms, ticket
  flags/lifetimes, and credential *types*. This keeps `ls`/`describe` fast and
  usable while locked. Treat the `.kvault` file as sensitive regardless, and
  keep it in the engagement workspace. (A future flag may seal metadata too.)
- **Unlock agent.** After `unlock`, the DEK lives in a short-lived agent
  process and is served over a `0600` per-vault unix socket (same-user only,
  same trust boundary as `ssh-agent`). `lock` or the TTL ends it.
- The `.gitignore` excludes `*.kvault`, `*.ccache`, `*.kirbi`, and PFX files so
  you don't commit material by accident.

## Limitations / roadmap

Honest about what v1 does **not** do yet:

- **No PAC decoding.** `describe` shows a ticket's envelope (client, SPN,
  flags, lifetime, etype) — the same data `klist` shows. It does **not** decode
  the PAC (group SIDs, privileged-group flags), because that lives in the
  ticket's encrypted part and needs the service/krbtgt key, which a captured
  ticket doesn't carry. Opportunistic PAC decode for tickets whose key you
  *do* hold (e.g. forged tickets) is a candidate for a later version, which
  would also enable automatic tier-0/DA tagging.
- **Metadata is plaintext** in the vault file (see security model).
- **No ticket requesting/renewal yet.** `krbvault` stores and serves material;
  it doesn't mint TGTs from a stored key, run S4U, auto-renew renewable TGTs,
  or turn a PFX into a TGT via PKINIT. Those are planned (`request` / `renew` /
  a keepalive).
- **No clock-skew handling.** If the host clock is off from the DC you'll still
  see `KRB_AP_ERR_SKEW` from downstream tools.

## License

MIT.
