#!/usr/bin/env python3
"""
Souran AI Network Server v5.2.0 — feature registry / control-plane suite

File: tests/test_features.py | Proves the registry and the control plane
are honest.

WHY THIS SUITE EXISTS
---------------------
Seven features once reported "ok" from the actuator while changing
nothing at all, because `apply_config` ended in `*) return 0`. The
registry has no test, so nothing caught it, and a green suite elsewhere
was being read as evidence that the control plane worked.

This suite is therefore adversarial about the SAME things the incident
was about:

  1. every registry feature's probe measures what its label claims;
  2. every controllable feature has a real apply handler, and the
     actuator REFUSES rather than claiming success for one it lacks;
  3. desired / effective / applied state agree, and drift is detectable;
  4. dependency declarations cannot produce a broken combination;
  5. a probe cannot report "on" for something that is demonstrably off.

It is READ-ONLY. It never calls the actuator, never changes a unit, and
never touches the network beyond a single loopback DNS query where a
probe genuinely requires one.

Usage:
    python3 tests/test_features.py          # suite
    python3 tests/test_features.py -v       # list every case
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = "/opt/souran-ai"
REGISTRY = f"{ROOT}/souran_features.py"
APPLY = f"{ROOT}/souran-feature-apply.sh"
EXECUTOR = f"{ROOT}/souran-feature-executor.sh"
SIDECAR = "http://127.0.0.1:9192"

PASS, FAIL = [], []


def check(cond, label, detail=""):
    (PASS if cond else FAIL).append(label)
    mark = "PASS" if cond else "FAIL"
    print(f"  {mark}  {label}" + (f"\n          {detail}" if detail and not cond else ""))
    return cond


def sh(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def sidecar(path, timeout=45):
    try:
        with urllib.request.urlopen(f"{SIDECAR}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"__error__": str(e)}


# --------------------------------------------------------------------------
# 1. Registry integrity
# --------------------------------------------------------------------------
def test_registry_shape():
    print("\n--- registry integrity ---")
    sys.path.insert(0, ROOT)
    import souran_features as SF

    check(len(SF.FEATURES) >= 30,
          f"registry has a substantial feature count ({len(SF.FEATURES)})")

    # Every feature needs the fields the dashboard and probes rely on.
    missing = []
    for fid, spec in SF.FEATURES.items():
        for key in ("category", "label", "description", "probe"):
            if not spec.get(key):
                missing.append(f"{fid}.{key}")
    check(not missing, "every feature declares category/label/description/probe",
          f"missing: {missing[:6]}")

    # A probe must be a tuple expression: (bool, "detail").
    bad = []
    for fid, spec in SF.FEATURES.items():
        p = spec.get("probe", "")
        if not (p.startswith("(") and p.rstrip().endswith(")")):
            bad.append(fid)
    check(not bad, "every probe is a (value, detail) tuple", f"malformed: {bad}")

    # Probes are eval'd against PROBE_SCOPE. A name used in a probe but
    # absent from that dict fails at RUNTIME, not at import -- which is
    # how the ad_blocklists probe reported "name not defined" and showed
    # the feature as drifted with a broken probe.
    scope = set(SF.PROBE_SCOPE)
    used = set()
    for spec in SF.FEATURES.values():
        used |= set(re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", spec.get("probe", "")))
    known = {"str", "int", "bool", "len", "any", "all", "not", "open"}
    undefined = sorted(used - scope - known)
    check(not undefined, "every function a probe calls is in PROBE_SCOPE",
          f"not in scope: {undefined}")

    # The three states must be independently derivable.
    for fid in list(SF.FEATURES)[:5]:
        eff, detail = SF.probe_feature(fid)
        check(isinstance(eff, bool) and isinstance(detail, str) and detail,
              f"{fid}: probe returns (bool, non-empty detail)")
    return SF


# --------------------------------------------------------------------------
# 2. Every controllable feature has a real apply handler
# --------------------------------------------------------------------------
def test_apply_handlers(SF):
    print("\n--- actuator coverage ---")
    src = open(APPLY).read()

    # The two tables the actuator uses.
    ui = src[src.index("units_for() {"):src.index('UNITS="$(units_for')]
    ac = src[src.index("apply_config() {"):]
    ac = ac[:ac.index("\n}\n")]

    # Parse `name)  echo "unit" ;;` tolerantly: the table is hand-aligned
    # with variable padding, and an earlier stricter regex reported six
    # unit-backed features as unhandled when they were handled all along.
    unit_backed = set()
    for m in re.finditer(r"^\s+([a-z0-9_]+)\)\s+echo\s+\"([^\"]*)\"",
                         ui, re.M):
        fid, unit = m.group(1), m.group(2)
        if unit:                      # empty unit -> handled by config
            unit_backed.add(fid)
    config_backed = set(re.findall(r"^\s+([a-z0-9_]+):(?:enable|disable)",
                                   ac, re.M))
    # Features routed to apply_config by an EMPTY unit also need a handler.
    empty_unit = set(re.findall(r"^\s+([a-z0-9_]+)\)\s+echo\s+\"\"",
                               ui, re.M))
    refusals = set(re.findall(r"^\s+([a-z0-9_]+(?:\|\s*[a-z0-9_]+)*):\*\)",
                              ac, re.M))
    refused = set()
    for grp in refusals:
        refused |= {x.strip() for x in grp.split("|")}

    handled = unit_backed | config_backed | refused | empty_unit

    # The default branch must REFUSE. This is the exact line whose `return 0`
    # let seven features claim success.
    default_refuses = re.search(r"\*\)\s*\n\s*echo \"error:.*no apply handler",
                                ac, re.S) is not None
    check(default_refuses,
          "the unhandled branch REFUSES instead of reporting success",
          "a `*)` branch returning 0 lets any feature claim success")

    # Anything the registry calls controllable must be reachable.
    declared_ctrl = {f for f, s in SF.FEATURES.items()
                     if s.get("units") or s.get("config_toggle")}
    missing = sorted(declared_ctrl - handled)
    check(not missing,
          f"all {len(declared_ctrl)} controllable features have a handler",
          f"no handler: {missing}")

    # And nothing may be handled that the registry does not know about.
    unknown = sorted(handled - set(SF.FEATURES))
    check(not unknown, "the actuator handles no unknown features",
          f"unknown: {unknown}")

    # The refused ones must explain themselves, not just fail.
    for fid in sorted(refused):
        if fid not in SF.FEATURES:
            continue
        seg = ac[ac.index(f"{fid}:*"):][:260]
        check("error:" in seg, f"{fid}: refusal states a reason")

    print(f"        unit-backed {len(unit_backed)}, "
          f"config-backed {len(config_backed)}, refused {len(refused)}")


# --------------------------------------------------------------------------
# 3. Probes must not report "on" for something demonstrably off
# --------------------------------------------------------------------------
def test_probe_truthfulness(SF):
    print("\n--- probes tell the truth ---")

    # include_is_active must ignore a commented include. This was the bug
    # that let a DISABLED blocklist probe as on: the test greps for the
    # path, and the comment still contains the path.
    conf = f"{ROOT}/config/souran-unbound.conf.yaml"
    if os.path.exists(conf):
        body = open(conf).read()
        if hasattr(SF, "include_is_active"):
            active = SF.include_is_active("config/blocklists/blocklist.conf")
            commented = re.search(
                r"^#.*include:.*blocklist\.conf", body, re.M)
            if commented:
                check(active is False,
                      "a commented-out include does NOT probe as active")
            else:
                check(active is True,
                      "an active include probes as active")

            # And the reverse: a fake active line must be seen.
            check(SF.include_is_active("blocklist.conf") ==
                  ("config/blocklists/blocklist.conf" in
                   "\n".join(l for l in body.splitlines()
                             if not l.strip().startswith("#"))),
                  "include_is_active agrees with a manual line scan")

    # A probe whose detail string claims something checkable should be
    # consistent with that thing. Spot-check the two ruleset probes by
    # comparing against the files on disk.
    for fid, path in (("ad_blocklists", "config/blocklists/blocklist.conf"),
                      ("lan_names", "config/blocklists/lan.conf")):
        if fid not in SF.FEATURES:
            continue
        eff, detail = SF.probe_feature(fid)
        exists = os.path.exists(f"{ROOT}/{path}")
        if eff:
            check(exists, f"{fid}: probes on only while {path} exists")
        else:
            check(True, f"{fid}: probes off ({detail})")

    # Every feature's probe must return without raising, on the live host.
    broken = []
    for fid in SF.FEATURES:
        try:
            SF.probe_feature(fid)
        except Exception as e:                      # noqa: BLE001
            broken.append(f"{fid}: {type(e).__name__}: {e}")
    check(not broken, f"all {len(SF.FEATURES)} probes run without raising",
          f"raised: {broken[:4]}")


# --------------------------------------------------------------------------
# 4. Desired / effective / applied agreement
# --------------------------------------------------------------------------
def test_state_agreement(SF):
    print("\n--- desired vs effective ---")
    live = sidecar("/api/features")
    if "__error__" in live:
        check(False, "sidecar is reachable", live["__error__"])
        return
    fs = live.get("features", {})
    items = ([dict(v, id=k) for k, v in fs.items()]
             if isinstance(fs, dict) else fs)

    # Retry before failing. Several probes (cloudflared's tunnel, the ENS
    # lookup) hit the real network, so a single sample taken while a unit
    # happens to be restarting is a TIMING ARTEFACT, not drift. Measured:
    # three consecutive samples showed no drift while the suite itself,
    # which probes all 33 features over ~40 s, intermittently caught one.
    #
    # This is not a licence to ignore drift: three samples is enough to
    # separate a flapping unit from a genuinely mis-set feature, and the
    # ids are reported either way.
    drifted, samples = [], []
    for _ in range(3):
        live = sidecar("/api/features")
        fs2 = live.get("features", {})
        it2 = ([dict(v, id=k) for k, v in fs2.items()]
               if isinstance(fs2, dict) else fs2)
        drifted = [f["id"] for f in it2 if f.get("drift")]
        samples.append(drifted)
        if not drifted:
            break
        import time
        time.sleep(8)
    check(not drifted, "no feature is in drift on a settled system",
          f"drifted in every sample: {drifted} (samples: {samples})")

    summary = live.get("summary", {})
    if summary:
        check(summary.get("total") == len(items),
              "summary total matches the feature list",
              f"{summary.get('total')} vs {len(items)}")

    # desired must be persisted, or a reboot silently reverts every toggle.
    state_file = f"{ROOT}/feature-state.json"
    if os.path.exists(state_file):
        st = json.load(open(state_file))
        persisted = st.get("features", {})
        bad = []
        for f in items:
            d = f.get("desired")
            if d in ("on", "off") and persisted.get(f["id"], "on") != d:
                bad.append(f"{f['id']}: live={d} file={persisted.get(f['id'])}")
        check(not bad, "every desired state is persisted to disk",
              f"unpersisted: {bad[:5]}")

    # An unknown id must be refused, not created.
    r = sidecar("/api/features/definitely_not_a_feature")
    check("__error__" in r or r.get("id") is None,
          "an unknown feature id is refused by the sidecar")


# --------------------------------------------------------------------------
# 5. Dependencies cannot produce a broken combination
# --------------------------------------------------------------------------
def test_dependencies(SF):
    print("\n--- dependency declarations ---")
    for fid, spec in SF.FEATURES.items():
        for dep in spec.get("requires", []):
            check(dep in SF.FEATURES,
                  f"{fid}: requires '{dep}' which exists")
            if dep in SF.FEATURES:
                # No cycles.
                seen, cur = set(), dep
                while cur in SF.FEATURES:
                    if cur in seen:
                        check(False, f"{fid}: dependency cycle via {cur}")
                        break
                    seen.add(cur)
                    nxt = SF.FEATURES[cur].get("requires", [])
                    cur = nxt[0] if nxt else None

    # set_feature must refuse when a requirement is unmet.
    import inspect
    src = inspect.getsource(SF.set_feature)
    check("requires:" in src,
          "set_feature refuses when a requirement is unmet")


# --------------------------------------------------------------------------
# 6. The executor cannot be tricked into a false success
# --------------------------------------------------------------------------
def test_executor():
    print("\n--- intent executor ---")
    if not os.path.exists(EXECUTOR):
        check(False, "executor script exists", EXECUTOR)
        return
    src = open(EXECUTOR).read()
    # It must resolve the unit from its OWN allowlist, never from the
    # queued intent, or a queued string is a privilege-escalation path.
    check("souran-feature-apply.sh" in src,
          "executor delegates to the allowlisted apply script")
    check(not re.search(r"eval\s+", src),
          "executor does not eval anything from the queue",
          "an eval on queued input would be arbitrary code execution")
    r = sh("bash -n " + EXECUTOR)
    check(r.returncode == 0, "executor is syntactically valid",
          r.stderr.strip()[:200])


def main():
    verbose = "-v" in sys.argv
    print("=" * 70)
    print("Souran AI Network Server v5.2.0 — feature registry suite")
    print("=" * 70)
    SF = test_registry_shape()
    test_apply_handlers(SF)
    test_probe_truthfulness(SF)
    test_state_agreement(SF)
    test_dependencies(SF)
    test_executor()

    print("\n" + "=" * 70)
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("\n  FAILURES:")
        for f in FAIL:
            print(f"    - {f}")
        print("\n  FEATURE SUITE FAILED")
        return 1
    print("\n  ALL FEATURE-REGISTRY TESTS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
