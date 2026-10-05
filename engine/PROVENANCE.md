# Resolver provenance — unbound

## What is actually running

    Version 1.26.2
    sha256 of /opt/souran-ai/engine/unbound/sbin/unbound
      aecb9e05b9e141a4439cefbfa0c2de38…

## 1.26.2 DOES NOT EXIST AS A RELEASE

Verified against nlnetlabs.nl:

    unbound-1.26.2.tar.gz  -> HTTP 404
    unbound-1.26.1.tar.gz  -> HTTP 200
    unbound-1.26.0.tar.gz  -> HTTP 200

1.26.1 is the newest published release. The tree this project builds is
NLnetLabs/unbound at:

    commit a7fc80d8c5dd6215c52570dd281ec58d04d25eea
    2026-09-16  "Unit test for CVE-2026-85501"

which reports itself as 1.26.2 and sits ahead of the release-1.26.1 tag.
It is therefore an UNRELEASED development tree.

## Why 1.26.1 must NOT be substituted

An audit recommended replacing this tree with upstream 1.26.1 on the
grounds that the CVE fix is already in 1.26.1. **That is false**, and
following it would have downgraded the resolver to a vulnerable build.
Checked by counting the fix's symbols in both trees:

                          upstream 1.26.1   this tree
    val_nsec3.c: nsec3_algo_has_hashlen        0              2
    val_utils.c: val_has_auth_nsecs            0              1

Upstream 1.26.1 has neither. Its `nsec3_get_algo()` and
`nsec3_known_algo()` are byte-identical to the pre-fix versions.

## What the fix actually is

CVE-2026-85501 is CWE-770, uncontrolled resource consumption, in DNSSEC
validation. The defect is an **unchecked NSEC3 hash length** in
`validator/val_nsec3.c`: `nsec3_get_algo()` returns the algorithm byte and
the hash length was taken from the record without being validated against
it, so a record claiming SHA1 with a longer or shorter hash drives an
unbounded amount of hashing work. This tree adds:

  * `nsec3_algo_has_hashlen()` — rejects any algorithm whose hash length
    does not match, and rejects unknown algorithms outright
  * `NSEC3_SHA_LEN` in `validator/val_nsec3.h`
  * an over-long label check before the hash is computed
  * `val_has_auth_nsecs()` in `validator/val_utils.c`, used at
    `validator/validator.c:3189` to report which denial type actually
    caused a bogus referral

## Reproducing this build

The tree is not a tarball download, because no such tarball is published.
It is fetched by COMMIT from the canonical upstream repository:

    git clone https://github.com/NLnetLabs/unbound.git
    git -C unbound checkout a7fc80d8c5dd6215c52570dd281ec58d04d25eea

That is the recipe `fetch-unbound.sh` implements, and it is pinned to the
commit rather than to a version string precisely because "1.26.2" cannot
be resolved by anyone.

## Note on checking the installed binary

Both the built and the installed binaries are **stripped**, so `nm` cannot
confirm the fix in either. Do not read that absence as a missing patch.

The fix is confirmed two other ways, both of which are automated:

  1. `fetch-unbound.sh` verifies the guard is present in the source tree
     **before** building (`grep nsec3_algo_has_hashlen`), so a tree without
     the patch is never built in the first place.
  2. `configure && make` must succeed, and it cannot link if
     `nsec3_algo_has_hashlen` is called but not defined.

`build-deb-payload.sh` additionally refuses to package any resolver whose
`-V` output is not exactly `1.26.2`, and fails closed when no resolver
binary is present at all.

## Verified end to end

From a directory containing nothing but this repository:

    ./fetch-unbound.sh /tmp/check         # ~30 s via Tor
    cd /tmp/check && ./configure ... && make -j$(nproc)   # ~105 s

    -> Version 1.26.2
    -> nsec3_algo_has_hashlen present in validator/val_nsec3.c

A full `git clone` of unbound is NOT used: it pulls roughly 200 MB of
history and over Tor it did not finish in 800 s. The script does
`git init` + `fetch --depth 1 <commit>`, which takes about 20 s, because
the pinned commit is not a branch tip and so cannot be shallow-cloned
directly.
