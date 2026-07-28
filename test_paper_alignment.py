#!/usr/bin/env python3
"""
Tests for the code changes that align the implementation with the paper:
  N10 verifier hardening + can_id==0 fix
  N2  adaptive Mahalanobis threshold (Eq. 1)
  N3  multi-level trust (Eq. 2)
  N4  Attack Severity Index (Eq. 3)
"""

import sys
sys.path.insert(0, '/Users/adhnanjeff/Desktop/Final Project')

from security import MessageSigner, MessageVerifier
from mahalanobis_detector import AdaptiveMahalanobisDetector, FEATURE_NAMES
from risk_index import compute_attack_severity_index, severity_grade
from trust_engine import TrustEngine

print("=" * 60)
print("Paper-alignment tests")
print("=" * 60)

# ---------------------------------------------------------------------------
# N10 + can_id==0 fix (verifier)
# ---------------------------------------------------------------------------
print("\n[N10] verifier: can_id 0x000 accepted, replay rejected")
signer = MessageSigner("vehicleA-speed-ecu")
verifier = MessageVerifier()

# can_id == 0 must be accepted (previously rejected by the all([...]) bug)
msg0 = signer.sign_message(0x000, b"\x01\x02")
ok, reason = verifier.verify_message(msg0)
assert ok, f"can_id 0x000 should verify, got: {reason}"
print("  ✅ can_id 0x000 verified")

# strictly increasing sequence accepted
msg1 = signer.sign_message(0x130, b"\x01\x02")
ok, reason = verifier.verify_message(msg1)
assert ok, f"expected accept, got {reason}"

# replay of the SAME message (same sequence) must be rejected
ok, reason = verifier.verify_message(msg1)
assert not ok and "replay" in reason.lower(), f"replay should be rejected, got {ok}/{reason}"
print("  ✅ sequence replay rejected")

# a large negative sequence jump (not a fresh start) must NOT be auto-accepted
forged = dict(msg1)
forged["sequence"] = msg1["sequence"] - 500
# (signature won't match anyway, but the sequence guard should trip first or the
#  signature check should fail; either way it must be rejected)
ok, _ = verifier.verify_message(forged)
assert not ok, "forged low-sequence frame must be rejected"
print("  ✅ forced sequence rollback rejected")

# ---------------------------------------------------------------------------
# N2 adaptive Mahalanobis threshold (Eq. 1)
# ---------------------------------------------------------------------------
print("\n[N2] adaptive Mahalanobis threshold tau(t)=tau0+aT+bsigma")
det = AdaptiveMahalanobisDetector(min_samples=15)
base = {n: 1.0 for n in FEATURE_NAMES}

tau_lo = det.adaptive_threshold(trust=0.0, state_variability=0.0)
tau_trust = det.adaptive_threshold(trust=1.0, state_variability=0.0)
tau_var = det.adaptive_threshold(trust=0.0, state_variability=1.0)
assert tau_lo == det.tau0, "base threshold should equal tau0 when both terms are 0"
assert tau_trust > tau_lo, "higher trust must raise the threshold"
assert tau_var > tau_lo, "higher state variability must raise the threshold"
print(f"  ✅ tau0={tau_lo:.2f}, +trust={tau_trust:.2f}, +variability={tau_var:.2f} (both raise tau)")

# warm up a baseline, then a clear outlier should exceed tau
for i in range(25):
    f = dict(base); f["value_variance"] = 1.0 + (i % 3) * 0.01
    det.observe_and_update("speed", f, speed=50.0)
outlier = dict(base); outlier["z_score"] = 15.0; outlier["frequency"] = 400.0; outlier["jitter"] = 60.0
dec = det.adaptive_decision("speed", outlier, speed=50.0, trust=0.9, state_variability=0.0)
assert dec["distance"] > 0.0, "distance should be computed after warm-up"
assert dec["is_anomaly"] == 1.0, "clear outlier should exceed adaptive threshold"
print(f"  ✅ outlier D_M={dec['distance']:.1f} > tau={dec['threshold']:.1f} -> anomaly")

# ---------------------------------------------------------------------------
# N4 Attack Severity Index (Eq. 3)
# ---------------------------------------------------------------------------
print("\n[N4] Attack Severity Index")
low = compute_attack_severity_index(mahalanobis_norm=0.0, trust_overall=1.0, hmac_failure_rate=0.0)
high = compute_attack_severity_index(mahalanobis_norm=1.0, trust_overall=0.1, hmac_failure_rate=1.0)
assert low == 0.0, f"expected 0.0, got {low}"
assert high > 0.75, f"expected severe, got {high}"
# H term must matter (non-constant): more HMAC failures -> higher ASI
h0 = compute_attack_severity_index(0.2, 0.9, 0.0)
h1 = compute_attack_severity_index(0.2, 0.9, 0.8)
assert h1 > h0, "higher HMAC failure rate must raise ASI"
assert severity_grade(low) == "LOW" and severity_grade(high) == "CRITICAL"
print(f"  ✅ ASI low={low:.3f}(LOW), high={high:.3f}(CRITICAL), H-term active ({h0:.3f}->{h1:.3f})")

# ---------------------------------------------------------------------------
# N3 multi-level trust (Eq. 2)
# ---------------------------------------------------------------------------
print("\n[N3] multi-level trust")
te = TrustEngine()
assert abs(te.get_trust_score() - 1.0) < 1e-9
comps = te.get_component_trusts()
assert set(comps) == {"t_msg", "t_node", "t_behavior"}
# an HMAC failure must lower message trust and thus overall trust
before = te.get_trust_score()
te.record_auth_outcome(False)
assert te.get_component_trusts()["t_msg"] < 1.0, "auth failure must lower t_msg"
assert te.get_trust_score() < before, "auth failure must lower overall trust"
# a high anomaly must lower node+behavior trust
te2 = TrustEngine()
te2.update_trust(anomaly_score=0.9, auth_result=1.0, temporal_score=0.5)
c = te2.get_component_trusts()
assert c["t_behavior"] < 0.5 and c["t_node"] < 1.0, "anomaly must lower behavior/node trust"
# overall is exactly the weighted sum
expected = te2.w_msg*c["t_msg"] + te2.w_node*c["t_node"] + te2.w_behavior*c["t_behavior"]
assert abs(te2.get_trust_score() - expected) < 1e-9, "overall must equal weighted component sum"
print(f"  ✅ components fuse to weighted overall; auth+anomaly both lower trust")

print("\n" + "=" * 60)
print("All paper-alignment tests passed!")
print("=" * 60)
