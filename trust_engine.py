import time
from storage import get_storage_manager


def _clamp(value, low=0.0, high=1.0):
    return max(low, min(high, value))


class TrustEngine:
    """Multi-level trust engine (paper Eq. 2).

    Instead of a single recursive score, trust is decomposed into three
    components and fused with weights:

        T_overall = w_msg * T_msg + w_node * T_node + w_behavior * T_behavior

    * T_msg      – Message trust from HMAC verification. An EWMA of per-message
                   authentication outcomes (1.0 pass, 0.0 fail). Because failed
                   or unsigned messages are dropped before scoring, callers feed
                   those outcomes in via ``record_auth_outcome`` so this term
                   reflects the real recent HMAC pass-rate, not a constant 1.0.
    * T_node     – Node trust from the ECU's historical behavior. A recursive
                   decay/recovery score (preserves temporal memory: it erodes
                   under sustained anomalies and rebuilds during clean traffic).
    * T_behavior – Behavior trust from the current ML/Mahalanobis anomaly
                   (instantaneous: 1 - anomaly_score).

    Weights default to (0.3, 0.4, 0.3) and sum to 1.0 so T_overall stays in
    [0, 1]. The previous single-score recursive model is retained as the T_node
    component, so existing policy/IPS thresholds continue to behave sensibly.
    """

    def __init__(self, w_msg=0.3, w_node=0.4, w_behavior=0.3,
                 node_decay=0.15, node_temporal=0.05, recovery_rate=0.03,
                 msg_ewma=0.2, vehicle_id="vehicleA"):
        # Fusion weights (paper Eq. 2). Kept normalized (sum = 1).
        self.w_msg = w_msg
        self.w_node = w_node
        self.w_behavior = w_behavior

        # T_node dynamics (historical behavior). node_decay/node_temporal are
        # the anomaly/temporal decay weights; recovery_rate rebuilds trust.
        self.node_decay = node_decay
        self.node_temporal = node_temporal
        self.recovery_rate = recovery_rate

        # EWMA weight for the message-trust update.
        self.msg_ewma = msg_ewma

        self.vehicle_id = vehicle_id

        # Component trust values.
        self.t_msg = 1.0
        self.t_node = 1.0
        self.t_behavior = 1.0

        # Fused overall trust.
        self.trust_score = 1.0

        self.min_trust = 0.0
        self.max_trust = 1.0
        self.last_update = time.time()

        # ML toggle (unchanged semantics: off => ignore anomaly influence).
        self.ml_enabled = True

        self.storage = get_storage_manager()

    # ------------------------------------------------------------------
    # Component updates
    # ------------------------------------------------------------------
    def record_auth_outcome(self, passed: bool):
        """Fold one HMAC verification outcome into T_msg (message trust).

        Call this for EVERY message that reaches the gateway, including those
        dropped for a missing/invalid signature (passed=False), so T_msg
        reflects the true recent authentication pass-rate.
        """
        sample = 1.0 if passed else 0.0
        self.t_msg = (1 - self.msg_ewma) * self.t_msg + self.msg_ewma * sample
        self.t_msg = _clamp(self.t_msg)
        self._recompute_overall()
        return self.t_msg

    def update_trust(self, anomaly_score, auth_result=1.0, temporal_score=1.0):
        """Update node/behavior trust from an authenticated, scored message.

        ``auth_result`` (1.0 pass) is also folded into T_msg so authenticated
        traffic pushes message trust back up; the drop path uses
        ``record_auth_outcome`` for failures.
        """
        current_time = time.time()

        # Message trust: this message authenticated successfully to be scored.
        self.t_msg = (1 - self.msg_ewma) * self.t_msg + self.msg_ewma * float(auth_result)
        self.t_msg = _clamp(self.t_msg)

        # ML toggle: ignore anomaly influence when ML is disabled.
        effective_anomaly = anomaly_score if self.ml_enabled else 0.0

        # Node trust: recursive decay/recovery (historical behavior).
        node_delta = 0.0
        if effective_anomaly > 0.3:
            node_delta -= self.node_decay * effective_anomaly
            node_delta -= self.node_temporal * (1 - temporal_score)
        if effective_anomaly < 0.2:
            node_delta += self.recovery_rate
        self.t_node = _clamp(self.t_node + node_delta)

        # Behavior trust: instantaneous complement of the anomaly score.
        self.t_behavior = _clamp(1.0 - effective_anomaly)

        self._recompute_overall()
        self.last_update = current_time

        # Log to storage (async, non-blocking); ignore failures.
        try:
            self.storage.log_trust_update(
                self.vehicle_id, self.trust_score, self.ml_enabled, anomaly_score
            )
        except Exception:
            pass

        return self.trust_score

    def _recompute_overall(self):
        self.trust_score = _clamp(
            self.w_msg * self.t_msg
            + self.w_node * self.t_node
            + self.w_behavior * self.t_behavior
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------
    def get_trust_score(self):
        return self.trust_score

    def get_component_trusts(self):
        """Return the three component trusts (for ASI/reporting)."""
        return {"t_msg": self.t_msg, "t_node": self.t_node, "t_behavior": self.t_behavior}

    def get_trust_level(self):
        if self.trust_score > 0.8:
            return "HIGH"
        elif self.trust_score > 0.6:
            return "MEDIUM"
        elif self.trust_score > 0.4:
            return "LOW"
        else:
            return "CRITICAL"

    def reset_trust(self):
        self.t_msg = 1.0
        self.t_node = 1.0
        self.t_behavior = 1.0
        self.trust_score = self.max_trust
        self.last_update = time.time()

    def set_ml_enabled(self, enabled):
        self.ml_enabled = enabled

    def is_ml_enabled(self):
        return self.ml_enabled

    def get_security_mode(self):
        return "CRYPTO_PLUS_ML" if self.ml_enabled else "CRYPTO_ONLY"

    def set_ips_active(self, active: bool):
        self._ips_active = active

    def get_status(self):
        return {
            "trust_score": self.trust_score,
            "trust_level": self.get_trust_level(),
            "last_update": self.last_update,
            "ml_enabled": self.ml_enabled,
            "security_mode": self.get_security_mode(),
            "components": self.get_component_trusts(),
            "weights": {
                "w_msg": self.w_msg,
                "w_node": self.w_node,
                "w_behavior": self.w_behavior,
            },
        }
