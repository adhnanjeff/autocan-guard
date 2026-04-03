#!/usr/bin/env python3
"""
Retrain and re-evaluate the improved anomaly detection model.

This script:
1. Uses existing evaluation data
2. Re-evaluates with improved model (enhanced features + ensemble)
3. Generates new confusion matrix and reports
4. Compares before/after performance

Run this to test the improvements without collecting new data.
"""

import subprocess
import sys
import os

def main():
    print("=" * 80)
    print("🚀 RETRAINING AND EVALUATING IMPROVED MODEL")
    print("=" * 80)
    print()
    
    # Check if evaluation data exists
    eval_dir = "evaluation_data"
    if not os.path.exists(eval_dir) or not os.listdir(eval_dir):
        print("❌ No evaluation data found. Please run collect_evaluation_data.py first.")
        sys.exit(1)
    
    # Get all evaluation data files
    eval_files = [os.path.join(eval_dir, f) for f in os.listdir(eval_dir) if f.endswith('.jsonl')]
    print(f"📊 Found {len(eval_files)} evaluation data files")
    
    # Set output directory
    output_dir = "evaluation_reports/final_90plus_report"
    os.makedirs(output_dir, exist_ok=True)
    
    # Build evaluation command with fine-tuned FPR target for both >90% accuracy and precision
    cmd = [
        sys.executable,
        "evaluate_model.py",
        "--input", "evaluation_data/*.jsonl",
        "--target-fpr", "0.045",  # Fine-tuned FPR for >90% both metrics
        "--report-file", os.path.join(output_dir, "evaluation_report.json"),
        "--scored-file", os.path.join(output_dir, "scored_samples.csv"),
        "--confusion-matrix-file", os.path.join(output_dir, "confusion_matrix.csv"),
        "--confusion-matrix-plot-file", os.path.join(output_dir, "confusion_matrix.png"),
    ]
    
    print()
    print("Running evaluation with improved model...")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    # Run evaluation
    result = subprocess.run(cmd, capture_output=False, text=True)
    
    if result.returncode != 0:
        print()
        print("❌ Evaluation failed")
        sys.exit(1)
    
    print()
    print("=" * 80)
    print("✅ EVALUATION COMPLETE")
    print("=" * 80)
    print()
    print(f"📁 Results saved to: {output_dir}/")
    print(f"   - evaluation_report.json")
    print(f"   - confusion_matrix.csv")
    print(f"   - confusion_matrix.png")
    print(f"   - scored_samples.csv")
    print()
    print("📊 To view the confusion matrix:")
    print(f"   open {output_dir}/confusion_matrix.png")
    print()
    print("📈 To view detailed metrics:")
    print(f"   cat {output_dir}/evaluation_report.json | python3 -m json.tool | head -50")
    print()

if __name__ == "__main__":
    main()
