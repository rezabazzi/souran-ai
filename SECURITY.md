# Security

## Known exposures: three credentials, all scrubbed from this repository

**None of these are still valid in this repository, and none were valid
when they were found.** The sudo password is the one only you can act on.
The other two were rotated or must be re-issued — see each entry.

### 1. The sudo password — ROTATE IT

This is the only exposure that requires an action from you that this
repository cannot perform.

An earlier version of this repository contained a plaintext sudo
password in `souran-toggle`, written as:

    sudo -S -p '' <<< "<password>" <command>

`-S` reads a credential from stdin. The value was a real root-adjacent
password belonging to the original operator.

**What has been done**

- Removed from all three call sites in the current tree; they use `sudo -n`.
- Rewritten across every commit in this repository's history with
  `git filter-branch`, the backup refs deleted, the reflog expired and
  the object store garbage-collected. Verified: 0 commits, 0 refs, 0 blobs
  and 0 unreachable objects contain the value.

**What has NOT been done, and what you must do**

Removing a credential from source does not un-leak it. It existed in
published history while the repository was tracked locally, and it may
have been read by anything with access to the machine or a clone taken
before the rewrite.

**If this is your deployment: rotate that sudo password now.** Treat it
as compromised regardless of how thoroughly it has been scrubbed.

Changing it means updating any NOPASSWD sudoers rules that reference the
old value, and re-testing the privileged paths
(`souran-feature-apply.sh`, `souran-firewall.sh`, `souran-certgen.sh`),
all of which use `sudo -n` and therefore depend on the sudoers policy
rather than on a stored password.

## Reporting a vulnerability

Open a GitHub issue or contact the operator directly. This is
infrastructure software running on a hostile network; please do not
disclose an exploit publicly before a fix exists.

## Security properties worth knowing about

| Area | Property |
|---|---|
| DNS poison detection | IPv4 **and** IPv6, including this network's string-appended AAAA forgery. A detected poison is never served, even when every encrypted tier is unreachable. |
| Upstream | Zero forwarders. unbound resolves from the root hints. TCP is forced upstream because UDP/53 is forged on hostile networks. |
| Encrypted DNS | Local root CA plus a leaf carrying DNS and IP SANs. Trusting a local root is the correct model: DoT authenticates the channel to *your* resolver. |
| Control plane | 0600 token, constant-time compare. The reverse proxy gates `/api/*` with `auth_request`; anonymous access returns 401. |
| Firewall | nftables, INPUT default-deny, owned by systemd so it survives reboot. OUTPUT is deliberately unfiltered — see README. |
| Secrets | Never in source, never in the package, never in git history. The package build refuses to proceed if a private key reaches the payload. |

## Known limitations

Stated plainly rather than left to be discovered:

- **DNSSEC validation is off by default.** Tor's exits strip RRSIG
  records, so strict validation cannot complete over that transport and
  fails closed. The defences that remain are forced-TCP upstream, the DoH
  tier and the private-address filter.
- **DoQ and DoH3 are unavailable.** unbound here is built without
  `ngtcp2`. Both need it.
- **An open resolver on the LAN** (`:53`) is a DNS-abuse amplifier if
  this host is ever NAT-forwarded. That is the intended deployment, but
  it is a real consideration.

### 2. A Technitium API token — ROTATED, but treat the old one as burned

A 64-hex token was committed in `dns/api-key.txt` in the initial commit
and reachable from every tag. It was later *untracked* — committed as a
deletion — which is not the same as being removed: the blob stayed in
history and on GitHub.

It was **live** at the time it was found: `/etc/dns/api-token.txt` held
the byte-identical value, and that file was read by the dashboard unit,
both watchdogs and two migration scripts. It has been replaced with a
freshly generated token and the 0600 copy at
`/opt/souran-ai/dns/api-key.txt` updated to match.

Scrubbing git while a credential still worked would have changed nothing,
which is why the rotation happened first.

### 3. A TLS private key — SCRUBBED, but the leaf must be re-issued

`dns/self-signed-cert.pfx` was committed in the same initial commit: an
empty-password PKCS#12 containing the DoT/DoH leaf private key. I
extracted it from history and confirmed it opens with an empty password,
so anyone holding it could impersonate the local resolver to any client
that trusts the CA.

**Outstanding, and it needs you:** re-issue the leaf so the PFX is
protected by a password.

    sudo /opt/souran-ai/souran-certgen.sh issue

## Why the obvious scan passes and this was still there

Every one of these was invisible to `git grep` over tracked files, because
the working tree was clean in all three cases. What finds them:

    git rev-list --objects --all              # every object any ref reaches
    git log --all --diff-filter=D --name-only # deletions that hide blobs

A file that was committed and then deleted shows up only as a *deletion*.
Searching the tip cannot see it.

Two further lessons, both learned here:

  * `git filter-branch --tree-filter 'rm -f X; git rm --cached X'` does
    not remove a blob. After `rm` deletes the file, `git rm` fails, and
    with its status swallowed the index keeps the blob. `--index-filter`
    is required for paths.
  * `--index-filter` then **reintroduced** a different secret, because it
    never touches file contents. Paths and contents need separate passes.
  * A stale `refs/remotes/origin/master` pins the pre-rewrite graph, so
    a rewrite can report success while every old object stays reachable.
