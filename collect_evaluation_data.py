#!/usr/bin/env python3
"""
Collect labeled evaluation data for anomaly detection and IPS behavior.

This script launches the local CAN generator + listener, records:
- normal windows (label=0)
- attack windows (label=1)

Output is a JSONL file in evaluation_data/ with per-sample timestamps,
scores, threshold, trust, IPS mode, and label metadata.
"""

import argparse
import threading
import time

from can_generator import CANMessageGenerator
from can_listener import CANListener
from ecu_compromise_attack import (
    attack_1_speed_manipulation,
    attack_2_steering_chaos,
    attack_3_kafka_pollution,
    attack_4_persistent_compromise,
)


ATTACK_FUNCTIONS = {
    "speed": attack_1_speed_manipulation,
    "steering": attack_2_steering_chaos,
    "kafka": attack_3_kafka_pollution,
    "persistent": attack_4_persistent_compromise,
}


def _sleep_with_progress(duration: float, label: str):
    end = time.time() + duration
    while time.time() < end:
        remaining = max(0.0, end - time.time())
        print(f"⏳ {label}: {remaining:4.1f}s remaining", end="\r")
        time.sleep(0.5)
    print(f"✅ {label}: complete{' ' * 20}")


def main():
    parser = argparse.ArgumentParser(description="Collect labeled CAN evaluation dataset.")
    parser.add_argument("--session-name", default="eval_run", help="Evaluation session/log prefix.")
    parser.add_argument("--normal-duration", type=float, default=25.0, help="Seconds of normal traffic before attacks.")
    parser.add_argument("--cooldown-duration", type=float, default=10.0, help="Seconds of normal traffic between attacks.")
    parser.add_argument(
        "--post-attack-duration",
        type=float,
        default=0.0,
        help="Optional seconds to keep attack label after each attack function returns.",
    )
    parser.add_argument("--training-timeout", type=float, default=40.0, help="Max seconds to wait for model training.")
    parser.add_argument(
        "--attacks",
        default="speed,steering,kafka",
        help="Comma-separated attack set: speed,steering,kafka,persistent",
    )
    args = parser.parse_args()

    requested_attacks = [item.strip().lower() for item in args.attacks.split(",") if item.strip()]
    unknown = [name for name in requested_attacks if name not in ATTACK_FUNCTIONS]
    if unknown:
        raise ValueError(f"Unknown attack names: {unknown}. Valid: {sorted(ATTACK_FUNCTIONS.keys())}")

    generator = CANMessageGenerator()
    listener = CANListener()

    generator_thread = threading.Thread(target=generator.start_simulation, daemon=True)
    generator_thread.start()
    listener.start_listening()

    try:
        log_path = listener.start_evaluation_session(args.session_name)
        print(f"📝 Logging evaluation data to: {log_path}")

        print("📚 Waiting for anomaly model training to complete...")
        train_start = time.time()
        while listener.training_mode and (time.time() - train_start) < args.training_timeout:
            elapsed = time.time() - train_start
            print(f"   training... {elapsed:4.1f}s", end="\r")
            time.sleep(0.5)
        print()

        if listener.training_mode:
            print("⚠️ Training did not complete before timeout; continuing with available model state.")
        else:
            print("✅ Training complete. Starting labeled collection.")

        # Baseline normal window
        listener.set_evaluation_label(0, "normal_baseline")
        _sleep_with_progress(args.normal_duration, "Normal baseline")

        # Attack scenarios
        for attack_name in requested_attacks:
            attack_func = ATTACK_FUNCTIONS[attack_name]
            print(f"🔥 Running attack scenario: {attack_name}")

            attack_start = time.time()
            listener.set_evaluation_label(1, attack_name)
            attack_func()
            attack_runtime = time.time() - attack_start
            print(f"✅ Attack runtime ({attack_name}): {attack_runtime:.2f}s")

            if args.post_attack_duration > 0:
                _sleep_with_progress(args.post_attack_duration, f"Post-attack window ({attack_name})")

            listener.set_evaluation_label(0, "normal_cooldown")
            _sleep_with_progress(args.cooldown_duration, f"Cooldown ({attack_name})")

        status = listener.get_evaluation_status()
        print("✅ Dataset collection complete.")
        print(f"   Log file: {status['log_path']}")
        print(f"   Samples:  {status['samples']}")

    finally:
        listener.stop()
        generator.stop()
        print("🛑 Collection pipeline stopped.")


if __name__ == "__main__":
    main()
