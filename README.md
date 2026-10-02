<p align="center">
  <img src="assets/goad_logo.png" alt="goad" width="200"/>
</p>

# gonetexec (`gnx`)

A modular, multi-protocol network execution and enumeration tool for
authorized security assessments — in the spirit of NetExec/CrackMapExec, written
in Go. Protocol work (SMB, LDAP, Kerberos, DCERPC) is delegated to
[`mandiant/gopacket`](https://github.com/mandiant/gopacket) rather than
re-implemented.

> The module path is `github.com/5amu/gonetexec`; the built binary is `gnx`.

## Build

```sh
cd cmd/gnx
go build .      # produces ./gnx
```

Requirements: Go 1.24+. Release builds are produced with GoReleaser
(`CGO_ENABLED=1`, static, trimmed).

## Targets and credentials

Every subcommand takes one or more targets as positional arguments. A target
may be:

- a single host or IP — `dc01.corp.local`, `10.0.0.5`
- a CIDR range — `10.0.0.0/24` (network/broadcast addresses are skipped for
  `/30` and larger; `/31` and `/32` keep every address)
- a path to a file containing one target per line (hosts and CIDRs)

`--username`/`-u` and `--password`/`-p` accept either a literal value or a path
to a file with one entry per line. When multiple usernames and passwords are
supplied they are combined as a **cluster bomb** (every user × every password)
by default. Most modules only act once credentials are supplied; with none they
perform a safe, read-only fingerprint/banner grab.

Outbound connections honour a configured SOCKS proxy through the shared
transport layer (`--proxy` semantics of `mandiant/gopacket`).

## Modules

### `smb`
SMB fingerprint, authentication, share enumeration, command execution and an
interactive client.

- default (with `-u`): authenticate and flag `Pwn3d!` when `ADMIN$` is writable
- `--shares`: list shares with read/write access
- `-x, --exec <cmd>`: execute a command via a temporary service over `svcctl`
- `--client`: interactive shell — `shares`, `use`, `cd`, `pwd`, `ls`, `tree`,
  `cat`, `get`, `put`, `mget`, `mkdir`, `rmdir`, `rm`, `rename`, `snapshots`
- `-H, --hashes`: pass-the-hash (`LM:NT` or `NT`)

### `ldap`
LDAP/AD enumeration and attack primitives.

- authentication (password, `-H` NTLM hash, `--null-session`)
- object enumeration: `--users`, `--active-users`, `--computers`, `--groups`,
  `--admin-count`, `--user <name>`, `--sid`, `--gmsa`
- bring-your-own `--filter` / `--attributes`, plus a large set of
  `userAccountControl` filter flags (composed with `--not` to negate)
- `--asreproast <file>` / `--kerberoast <file>`: harvest AS-REP / TGS hashes in
  hashcat format
- `--find-delegation`: enumerate unconstrained, constrained,
  protocol-transition and resource-based (RBCD) delegation
- `--add-computer` / `--del-computer`: create or remove a computer object

The search base is taken from the server's RootDSE `defaultNamingContext`,
falling back to a domain-derived DN.

### `krb`
Kerberos pre-authentication against a KDC.

- default: validate credentials against the KDC (`--dc-ip` optional)
- `--user-enum`: enumerate valid usernames / AS-REP roastable accounts
- `--pitchfork` / `--clusterbomb`: credential pairing strategy
- `--responder`: rogue SMB listener that captures NetNTLM hashes (experimental)

### `ssh`
- authenticate with a password or a private key (`-k`)
- `--exec <cmd>`: run a command; `--shell`: interactive shell
- banners are grabbed and fingerprinted up front

### `winrm`
- authenticate over WinRM (`--ssl` for HTTPS)
- `-x, --exec <cmd>`: run a command; `--shell`: interactive PowerShell
- the host label is enriched by a best-effort SMB fingerprint; WinRM still works
  when SMB/445 is unreachable

### `ftp`
- banner grab with no credentials
- `--list` / `--recursive-list`, `--get`/`--put` (with `--dst`), `--read`
- control and data connections both route through the transport dialer

### `vnc`
- detect RFB servers and test a password (`-p`)

## Disclaimer

For use only on systems you are explicitly authorized to test. You are
responsible for complying with all applicable laws.
