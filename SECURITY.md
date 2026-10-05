# Security

## Known exposure: rotate your sudo credential

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
