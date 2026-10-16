# krbvault

A consolidated, encrypted store for Kerberos tickets and credentials,
organized by identity, for authorized red-team and pentesting engagements.

On a large engagement your auth material sprawls: ccache files in `/tmp`, a few
`.kirbi`s, NT hashes and AES keys pasted into notes, a PFX or two. `krbvault`
keeps it all in one encrypted file per engagement, keyed on `user@REALM`, and
makes switching the active identity a single command.

> Authorized use only. This organizes material you have already obtained
> under a signed scope. If you discover a vulnerability while using it, report
> it to the vendor first.

## Why

Kerberos auth piles up fast on an engagement, and it piles up messy: a TGT in
`/tmp`, an NT hash and an AES key pasted into notes, a PFX from an AD CS abuse, a
service ticket you minted an hour ago and already can't find. krbvault makes the
identity the unit of organization — credentials and tickets are just material
hanging off a `user@REALM`, grouped by domain — and keeps all of it in one
encrypted vault per engagement. Because the secret-bearing material is sealed at
rest, a copy of the vault on the testing box isn't a plaintext credential dump.
What you get day to day is a tight loop: store what you capture, glance at what
you control and which tickets are still alive, switch the active identity with a
single command, and let your existing tools pick it up unchanged.

## Install

```bash
git clone https://github.com/cbev0x/krbvault
cd krbvault
pipx install .            # isolated, puts `krbvault` on PATH (recommended)
#   or, for development (with the test suite):
pip install -e '.[test]'
```

Requires Python 3.9+. Pulls in `pynacl` (crypto), `impacket` (ccache/kirbi
parsing + ticket requests + S4U), and `minikerberos` (PKINIT). Output is plain
ANSI — no heavy TUI dependency.

Keep it in its own environment. On Kali especially, a system-wide
`impacket` and a second copy in `~/.local` or a venv will shadow each other and
you'll get confusing `ImportError`s from the example scripts. `pipx` (above) or
a dedicated venv avoids this:

```bash
python3 -m venv ~/.venvs/krbvault && ~/.venvs/krbvault/bin/pip install .
```

PKINIT (`request --pfx`) needs `minikerberos`, which pulls `oscrypto`. Some
distros ship an OpenSSL whose version string older `oscrypto` can't parse
(`Error detecting the version of libcrypto`). If you hit that, upgrade it:
`pip install -U oscrypto` (≥ 1.3.1 reads `3.0.x` correctly).

S4U (`request --impersonate`) shells out to impacket's `getST`; it's
installed with impacket, so nothing extra is needed — just make sure the same
environment's `getST.py` / `impacket-getST` is on `PATH`.

One-time shell setup so tools read the active ticket (this is required — a
child process can't set your shell's `KRB5CCNAME`, so `use` swaps a file at a
fixed path and your shell must point at it):

```bash
krbvault env >> ~/.zshrc       # zsh (Kali default); use ~/.bashrc for bash
#   adds: export KRB5CCNAME="$HOME/.krbvault/active.ccache"
exec $SHELL                    # reload — or for just this shell: eval "$(krbvault env)"
```

`krbvault use` warns if `KRB5CCNAME` isn't wired up, and `krbvault status`
shows whether it's set in the current shell.

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

`use` points `KRB5CCNAME` at the chosen ticket so your existing tools run
unchanged — one command instead of exporting a cache path per invocation. When
you'd rather paste a command than switch the active cache, `emit` prints the
exact flag dialect for impacket, NetExec, or Rubeus from the material you've
stored, so you stop translating credentials into each tool's syntax by hand.

### Requesting and refreshing tickets

krbvault doesn't just hold material — it mints from it. `request` turns a stored
password, hash, or AES key into a TGT, a stored TGT into a service ticket, a
certificate into a TGT over PKINIT, or impersonates a user over S4U; `renew`
extends a renewable TGT. Everything it issues is filed straight back into the
vault.

```bash
# set the KDC for a realm once, so you can drop --dc from here on
krbvault -e acme config dc CORP.LOCAL 10.10.0.10

# mint a TGT from stored material (prefers AES; falls back as available)
krbvault -e acme request svc_sql@CORP.LOCAL

# a service ticket — reuses a stored TGT if present, else mints one from a key
krbvault -e acme request svc_sql@CORP.LOCAL --spn cifs/fs01.corp.local

# renew a renewable TGT before it dies (no key needed)
krbvault -e acme renew Administrator@CORP.LOCAL

# PKINIT: a TGT from a stored certificate
krbvault -e acme add alice@CORP.LOCAL --pfx loot/alice.pfx
krbvault -e acme request alice@CORP.LOCAL --pfx

# S4U (constrained delegation): a service ticket as another user, driven by a
# service account's TGT/key — no secrets ever touch the command line
krbvault -e acme request web01\$@CORP.LOCAL --spn cifs/fs01.corp.local \
    --impersonate Administrator
```

Add `--replace` to any `request`/`renew`/`import` to supersede the previous
ticket of the same kind+SPN instead of keeping both.

### Scripting

`ls`, `describe`, and `status` take `--json` for piping into `jq` or another tool:

```bash
krbvault -e acme ls --json | jq -r '.[] | select(.tickets | length > 0) | .upn'
krbvault -e acme status --json | jq .active
```

`ls` also drops to tab-separated rows (with a `REALM` column) whenever stdout
isn't a terminal, so `awk`/`cut` work without `jq`:

```bash
krbvault -e acme ls | awk -F'\t' '$6!="-"{print $2, $6}'   # identity + expiry
```

Colour follows `--color auto|always|never` (default `auto` — only on a TTY) and
honours `NO_COLOR`; `--no-color` is shorthand for `never`.

The `-e/--engagement` name selects the vault file. If you `cd` into a directory
that contains a `.krbvault/` folder, that engagement is used automatically.

## Commands

| Command | What it does |
|---|---|
| `init` | Create a new vault (prompts for a passphrase). |
| `unlock [--ttl]` / `lock` | Start/stop the unlock agent so you don't retype the passphrase. |
| `status` | Vault summary: identities, counts, lock state. |
| `import <file> [--identity] [--source] [--replace]` | Import a ccache or kirbi; auto-detects format, splits multi-credential caches, infers the identity. |
| `add <upn> --password/--nt/--aes256/--aes128/--rc4/--des/--pfx` | Store credential material for an identity. |
| `request <upn> [--spn] [--impersonate USER] [--pfx] [--ctype] [--dc] [--replace]` | Mint a TGT / service ticket / PKINIT TGT / S4U ticket from stored material. |
| `renew <upn \| #id> [--dc] [--replace]` | Renew a renewable TGT (no key needed). |
| `ls [--domain] [--json]` | Identities grouped by realm, with best-ticket health. |
| `describe <upn \| #id> [--json]` | Full detail for an identity or a specific ticket. |
| `status [--json]` | Vault summary: identities, counts, lock state, active ticket. |
| `use <upn \| #id> [--export] [--shell] [--for TOOL]` | Make a ticket the active `KRB5CCNAME`. |
| `emit <upn> --for TOOL [--target]` | Print impacket/nxc/Rubeus flags for the stored material. |
| `reveal <upn> [--ctype]` | Print a stored credential (PFX is written to a file). |
| `export <upn \| #id> [--kirbi] [-o]` | Write a stored ticket out to a `.ccache`/`.kirbi` file. |
| `purge [upn]` | Delete expired tickets (optionally just for one identity). |
| `rm <upn \| #id> [--ctype]` | Delete an identity, one ticket, or one credential type. |
| `config dc <REALM> <IP>` | Set (or `--unset`) the default KDC for a realm. |
| `env` | Print the `KRB5CCNAME` export line for your shell rc. |
| `passwd` | Re-wrap the vault under a new passphrase. |

### Switching modes

- default — `use` writes to the single active ccache the shell export
  points at. Simplest; one active identity at a time.
- `--export` — writes to a per-identity path and prints an
  `export KRB5CCNAME=…` line for `eval "$(krbvault use alice --export)"`, so
  several shells can hold different identities in parallel.
- `--shell` — drops you into a subshell scoped to that ticket; the ccache
  is cleaned up on exit.

## Security model

- Envelope encryption. Your passphrase is run through Argon2id to a key
  that wraps a random per-vault data key (DEK). Ticket bytes and credential
  values are sealed with the DEK using XChaCha20-Poly1305. Changing the
  passphrase re-wraps the DEK only — stored secrets are never re-encrypted.
- What's encrypted: the secret-bearing material — ticket blobs, passwords,
  NT/AES keys, PFX files.
- What's not encrypted: metadata — principals, SPNs, realms, ticket
  flags/lifetimes, and credential types. This keeps `ls`/`describe` fast and
  usable while locked. Treat the `.kvault` file as sensitive regardless, and
  keep it in the engagement workspace. (A future flag may seal metadata too.)
- Unlock agent. After `unlock`, the DEK lives in a short-lived agent
  process and is served over a `0600` per-vault unix socket (same-user only,
  same trust boundary as `ssh-agent`). `lock` or the TTL ends it.
- The `.gitignore` excludes `*.kvault`, `*.ccache`, `*.kirbi`, and PFX files so
  you don't commit material by accident.

## License

MIT.
