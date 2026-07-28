"""
Graded Risk Index

Trust score answers "does this sender still look legitimate?". It does not
distinguish *how dangerous* it would be to be wrong: a spoofed speed reading
and a spoofed steering command currently drive the exact same policy
response, even though loss of steering/brake control is far more safety
critical than a bad telemetry value. The risk index closes that gap by
combining trust, anomaly severity and contextual-physics violations with a
per-actuator criticality weight into one explainable [0, 1] number.

Scope (deliberate, current version): REPORTING ONLY. The risk index is
computed and logged/exposed for observability and the evaluation dataset; it
does not feed policy_engine.py or ips_engine.py, so it changes no existing
containment/actuation behaviour.
"""

from __future__ import annotations

from typing import Dict

# How safety-critical it is if THIS signal is being spoofed/manipulated.
# Steering and brake are direct actuation of vehicle control; speed is a
# telemetry/target value with an extra layer (IPS clamping) before it
# affects motion, so it is weighted lower.
DEFAULT_CRITICALITY_WEIGHTS: Dict[str, float] = {
    "steering": 1.0,
    "brake": 1.0,
    "speed": 0.6,
}

# Weighting of the three inputs into the base (pre-criticality) risk score.
TRUST_WEIGHT = 0.40
ANOMALY_WEIGHT = 0.35
CONTEXT_WEIGHT = 0.25

_RISK_LEVEL_THRESHOLDS = (
    ("SEVERE", 0.75),
    ("HIGH", 0.5),
    ("MODERATE", 0.25),
)


def compute_risk_index(
    trust_score: float,
    anomaly_severity: float,
    contextual_violation_score: float,
    signal_name: str,
    criticality_weights: Dict[str, float] = None,
) -> float:
    """Composite [0, 1] risk index for one CAN signal observation.

    Args:
        trust_score: current trust score in [0, 1] (1 = fully trusted).
        anomaly_severity: combined anomaly score in [0, 1] (e.g.
            ``total_anomaly_score`` from the multi-layer pipeline).
        contextual_violation_score: physics/context violation score in
            [0, 1] (e.g. from ContextualValidator.validate_context).
        signal_name: "steering" / "speed" / "brake" (or any key present in
            ``criticality_weights``); unknown signals default to weight 1.0
            (fail toward caution, not toward under-weighting risk).
        criticality_weights: override for DEFAULT_CRITICALITY_WEIGHTS.
    """
    weights = criticality_weights or DEFAULT_CRITICALITY_WEIGHTS
    trust_score = min(1.0, max(0.0, float(trust_score)))
    anomaly_severity = min(1.0, max(0.0, float(anomaly_severity)))
    contextual_violation_score = min(1.0, max(0.0, float(contextual_violation_score)))

    base_risk = (
        TRUST_WEIGHT * (1.0 - trust_score)
        + ANOMALY_WEIGHT * anomaly_severity
        + CONTEXT_WEIGHT * contextual_violation_score
    )
    criticality = weights.get(signal_name, 1.0)
    return min(1.0, max(0.0, base_risk * criticality))


def risk_level(risk_index: float) -> str:
    """Categorical label for a risk index value, for dashboards/reports."""
    for label, threshold in _RISK_LEVEL_THRESHOLDS:
        if risk_index >= threshold:
            return label
    return "LOW"


# ---------------------------------------------------------------------------
# Attack Severity Index (paper Eq. 3)
#   ASI = w1 * D_M(norm) + w2 * (1 - T_overall) + w3 * H
# where
#   D_M(norm)  – Mahalanobis distance normalized to [0, 1] (distance relative to
#                its adaptive threshold: min(1, D_M / tau)), so the term is
#                comparable with the other two and the ASI stays in [0, 1];
#   T_overall  – the multi-level trust score (Eq. 2);
#   H          – HMAC failure rate over the recent window, in [0, 1]. This is
#                the fraction of recent messages that failed authentication;
#                because failed/unsigned messages are dropped before scoring,
#                H is derived from the message-trust EWMA as H = 1 - T_msg,
#                which makes it a meaningful, non-constant signal.
# ---------------------------------------------------------------------------
ASI_W_DIST = 0.40
ASI_W_TRUST = 0.35
ASI_W_HMAC = 0.25

# Paper grades: low / medium / high / critical.
_ASI_GRADE_THRESHOLDS = (
    ("CRITICAL", 0.75),
    ("HIGH", 0.5),
    ("MEDIUM", 0.25),
)


def compute_attack_severity_index(
    mahalanobis_norm: float,
    trust_overall: float,
    hmac_failure_rate: float,
    weights=None,
) -> float:
    """Composite Attack Severity Index in [0, 1] (paper Eq. 3).

    Args:
        mahalanobis_norm: Mahalanobis distance normalized to [0, 1]
            (e.g. min(1, D_M / tau) against the adaptive threshold).
        trust_overall: multi-level trust score T_overall in [0, 1].
        hmac_failure_rate: H in [0, 1] (fraction of recent messages failing HMAC).
    """
    w1, w2, w3 = (weights or (ASI_W_DIST, ASI_W_TRUST, ASI_W_HMAC))
    d = min(1.0, max(0.0, float(mahalanobis_norm)))
    t = min(1.0, max(0.0, float(trust_overall)))
    h = min(1.0, max(0.0, float(hmac_failure_rate)))
    asi = w1 * d + w2 * (1.0 - t) + w3 * h
    return min(1.0, max(0.0, asi))


def severity_grade(asi: float) -> str:
    """Grade an ASI value as LOW / MEDIUM / HIGH / CRITICAL (paper)."""
    for label, threshold in _ASI_GRADE_THRESHOLDS:
        if asi >= threshold:
            return label
    return "LOW"
