"""
Comprehensive Evaluation Suite with Statistical Analysis
Generates performance metrics, confidence intervals, and graphs for academic reporting
"""

import time
import random
import statistics
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple
from collections import defaultdict

# Import visualization libraries
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("⚠️ matplotlib not available - install with: pip install matplotlib numpy")

from performance_monitor import performance_monitor
from security import MessageSigner, MessageVerifier

# Output directory for graphs and reports
OUTPUT_DIR = "/Users/adhnanjeff/Desktop/Final Project/evaluation_reports"


class EvaluationSuite:
    def __init__(self, num_runs: int = 5, messages_per_run: int = 1000):
        self.num_runs = num_runs
        self.messages_per_run = messages_per_run
        
        # Evaluation results
        self.run_data = []
        self.latency_samples = []
        self.throughput_samples = []
        
        # Ground truth labels
        self.ground_truth = []  # 0 = benign, 1 = attack
        self.predictions = []   # 0 = benign, 1 = attack
        
        # Security components
        self.signer = MessageSigner("vehicleA-speed-ecu")  # Use existing ECU key
        self.verifier = MessageVerifier()
        
        # Ensure output directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        print(f"📊 Evaluation Suite initialized")
        print(f"   • Runs: {num_runs}")
        print(f"   • Messages per run: {messages_per_run}")
        print(f"   • Total messages: {num_runs * messages_per_run}")
    
    def generate_test_message(self, is_attack: bool) -> Tuple[dict, bool]:
        """
        Generate test message following methodology:
        Mt → F(Mt) → Tt (Trust Score) → Dt (Decision)
        """
        can_id = random.choice([0x130, 0x120, 0x140])
        value = random.uniform(0, 100)
        data = int(value * 10).to_bytes(2, 'big') + b'\x00' * 6
        
        if is_attack:
            # Attack message: invalid signature
            message = {
                'can_id': can_id,
                'device_id': 'attacker-ecu',
                'payload': data.hex(),
                'signature': 'INVALID_ATTACK_SIGNATURE_XXXXXXXXXXXXXXXXXXXX',
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            # Benign message: valid signature
            message = self.signer.sign_message(can_id, data)
        
        return message, is_attack
    
    def verify_message(self, message: dict) -> Tuple[bool, float]:
        """
        Verify message and return (is_detected_as_attack, latency_ms)
        """
        start_time = time.perf_counter()
        
        # Verify signature
        is_valid, reason = self.verifier.verify_message(message)
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Decision: Dt = 1 if attack detected (invalid signature)
        is_attack_detected = not is_valid
        
        return is_attack_detected, latency_ms
    
    def run_single_evaluation(self, run_id: int) -> Dict[str, Any]:
        """Run a single evaluation with mixed benign/attack traffic"""
        print(f"\n🔄 Running evaluation {run_id + 1}/{self.num_runs}...")
        
        latencies = []
        results = []
        
        # Mix of benign (70%) and attack (30%) messages
        attack_ratio = 0.3
        
        start_time = time.time()
        
        for i in range(self.messages_per_run):
            # Generate message
            is_attack = random.random() < attack_ratio
            message, ground_truth = self.generate_test_message(is_attack)
            
            # Verify and measure
            detected_as_attack, latency_ms = self.verify_message(message)
            
            # Track results
            latencies.append(latency_ms)
            self.ground_truth.append(1 if ground_truth else 0)
            self.predictions.append(1 if detected_as_attack else 0)
            
            # Track for performance monitor
            performance_monitor.track_message_latency(latency_ms)
            performance_monitor.track_detection_result(detected_as_attack, ground_truth)
            
            # Calculate if correct
            correct = (detected_as_attack == ground_truth)
            results.append(correct)
        
        elapsed = time.time() - start_time
        throughput = self.messages_per_run / elapsed
        
        # Calculate run statistics
        run_stats = {
            "run_id": run_id + 1,
            "messages": self.messages_per_run,
            "elapsed_seconds": round(elapsed, 3),
            "throughput": round(throughput, 2),
            "latency": {
                "mean": round(statistics.mean(latencies), 3),
                "median": round(statistics.median(latencies), 3),
                "stdev": round(statistics.stdev(latencies), 3) if len(latencies) > 1 else 0,
                "p95": round(sorted(latencies)[int(len(latencies) * 0.95)], 3),
                "p99": round(sorted(latencies)[int(len(latencies) * 0.99)], 3)
            },
            "accuracy": round(sum(results) / len(results) * 100, 2)
        }
        
        self.run_data.append(run_stats)
        self.latency_samples.append(latencies)
        self.throughput_samples.append(throughput)
        
        # End run in performance monitor
        performance_monitor.end_run()
        
        print(f"   ✅ Run {run_id + 1}: Throughput={throughput:.0f} msg/s, Latency={run_stats['latency']['mean']:.2f}ms, Accuracy={run_stats['accuracy']:.1f}%")
        
        return run_stats
    
    def calculate_confidence_intervals(self) -> Dict[str, Any]:
        """Calculate 95% confidence intervals for all metrics"""
        
        def ci_95(data: List[float]) -> Dict[str, float]:
            """Calculate 95% CI"""
            n = len(data)
            if n < 2:
                mean = data[0] if data else 0
                return {"mean": mean, "ci_lower": mean, "ci_upper": mean, "stdev": 0, "margin": 0}
            
            mean = statistics.mean(data)
            stdev = statistics.stdev(data)
            # t-value approximation for 95% CI
            t_value = 2.0 if n < 30 else 1.96
            margin = t_value * (stdev / (n ** 0.5))
            
            return {
                "mean": round(mean, 3),
                "stdev": round(stdev, 3),
                "ci_lower": round(mean - margin, 3),
                "ci_upper": round(mean + margin, 3),
                "margin": round(margin, 3),
                "n": n
            }
        
        # Extract metrics from runs
        mean_latencies = [r["latency"]["mean"] for r in self.run_data]
        p95_latencies = [r["latency"]["p95"] for r in self.run_data]
        throughputs = [r["throughput"] for r in self.run_data]
        accuracies = [r["accuracy"] for r in self.run_data]
        
        return {
            "latency_mean": ci_95(mean_latencies),
            "latency_p95": ci_95(p95_latencies),
            "throughput": ci_95(throughputs),
            "accuracy": ci_95(accuracies)
        }
    
    def calculate_classification_metrics(self) -> Dict[str, float]:
        """Calculate precision, recall, F1, etc. from all runs"""
        # Build confusion matrix
        tp = sum(1 for g, p in zip(self.ground_truth, self.predictions) if g == 1 and p == 1)
        tn = sum(1 for g, p in zip(self.ground_truth, self.predictions) if g == 0 and p == 0)
        fp = sum(1 for g, p in zip(self.ground_truth, self.predictions) if g == 0 and p == 1)
        fn = sum(1 for g, p in zip(self.ground_truth, self.predictions) if g == 1 and p == 0)
        
        total = tp + tn + fp + fn
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        return {
            "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "specificity": round(specificity * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "accuracy": round(accuracy * 100, 2),
            "fpr": round(fpr * 100, 2),
            "fnr": round(fnr * 100, 2),
            "total_samples": total
        }
    
    def run_full_evaluation(self):
        """Run complete evaluation suite"""
        print("\n" + "=" * 70)
        print("🚀 STARTING COMPREHENSIVE EVALUATION")
        print("=" * 70)
        
        # Start monitoring
        performance_monitor.start_monitoring()
        
        # Run all evaluation rounds
        for i in range(self.num_runs):
            self.run_single_evaluation(i)
            time.sleep(0.5)  # Brief pause between runs
        
        # Calculate final metrics
        ci = self.calculate_confidence_intervals()
        classification = self.calculate_classification_metrics()
        
        # Generate report
        report = self.generate_report(ci, classification)
        
        # Generate graphs
        if MATPLOTLIB_AVAILABLE:
            self.generate_all_graphs(ci, classification)
        
        # Print summary
        self.print_evaluation_summary(ci, classification)
        
        # Stop monitoring
        performance_monitor.stop_monitoring()
        
        return report
    
    def generate_report(self, ci: Dict, classification: Dict) -> Dict:
        """Generate comprehensive evaluation report"""
        report = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "num_runs": self.num_runs,
                "messages_per_run": self.messages_per_run,
                "total_messages": self.num_runs * self.messages_per_run
            },
            "confidence_intervals": ci,
            "classification_metrics": classification,
            "per_run_data": self.run_data,
            "variance_analysis": {
                "latency_variance": round(statistics.variance([r["latency"]["mean"] for r in self.run_data]), 4) if len(self.run_data) > 1 else 0,
                "throughput_variance": round(statistics.variance([r["throughput"] for r in self.run_data]), 4) if len(self.run_data) > 1 else 0,
                "accuracy_variance": round(statistics.variance([r["accuracy"] for r in self.run_data]), 4) if len(self.run_data) > 1 else 0
            }
        }
        
        # Save report
        report_path = f"{OUTPUT_DIR}/evaluation_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Report saved: {report_path}")
        
        return report
    
    def generate_all_graphs(self, ci: Dict, classification: Dict):
        """Generate all evaluation graphs"""
        print("\n📊 Generating graphs...")
        
        # Set style
        plt.style.use('seaborn-v0_8-whitegrid')
        
        # 1. Latency Distribution Histogram
        self.plot_latency_distribution()
        
        # 2. Confidence Interval Plot
        self.plot_confidence_intervals(ci)
        
        # 3. Variance Across Runs
        self.plot_variance_across_runs()
        
        # 4. Throughput Over Runs
        self.plot_throughput_analysis()
        
        # 5. Confusion Matrix Heatmap
        self.plot_confusion_matrix(classification)
        
        # 6. Combined Performance Dashboard
        self.plot_performance_dashboard(ci, classification)
        
        print(f"✅ All graphs saved to: {OUTPUT_DIR}/")
    
    def plot_latency_distribution(self):
        """Plot latency distribution histogram with percentiles"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        # Flatten all latency samples
        all_latencies = [l for run in self.latency_samples for l in run]
        
        # Create histogram
        n, bins, patches = ax.hist(all_latencies, bins=50, color='steelblue', 
                                    edgecolor='white', alpha=0.7)
        
        # Add percentile lines
        p50 = statistics.median(all_latencies)
        p95 = sorted(all_latencies)[int(len(all_latencies) * 0.95)]
        p99 = sorted(all_latencies)[int(len(all_latencies) * 0.99)]
        
        ax.axvline(p50, color='green', linestyle='--', linewidth=2, label=f'P50: {p50:.2f}ms')
        ax.axvline(p95, color='orange', linestyle='--', linewidth=2, label=f'P95: {p95:.2f}ms')
        ax.axvline(p99, color='red', linestyle='--', linewidth=2, label=f'P99: {p99:.2f}ms')
        
        ax.set_xlabel('Latency (ms)', fontsize=12)
        ax.set_ylabel('Frequency', fontsize=12)
        ax.set_title('Message Processing Latency Distribution', fontsize=14, fontweight='bold')
        ax.legend(loc='upper right')
        
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/latency_distribution.png", dpi=150)
        plt.close()
        print("   ✓ latency_distribution.png")
    
    def plot_confidence_intervals(self, ci: Dict):
        """Plot confidence intervals for key metrics"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        
        metrics = [
            ("latency_mean", "Mean Latency (ms)", axes[0, 0]),
            ("latency_p95", "P95 Latency (ms)", axes[0, 1]),
            ("throughput", "Throughput (msg/s)", axes[1, 0]),
            ("accuracy", "Accuracy (%)", axes[1, 1])
        ]
        
        for metric_key, title, ax in metrics:
            data = ci[metric_key]
            
            # Create bar with error bar
            bar = ax.bar(["Value"], [data["mean"]], color='steelblue', alpha=0.7)
            ax.errorbar(["Value"], [data["mean"]], yerr=[[data["mean"] - data["ci_lower"]], 
                        [data["ci_upper"] - data["mean"]]], fmt='none', color='black', 
                        capsize=10, capthick=2, linewidth=2)
            
            # Add CI annotation
            ax.annotate(f'95% CI: [{data["ci_lower"]:.2f}, {data["ci_upper"]:.2f}]',
                       xy=(0, data["mean"]), xytext=(0.3, data["mean"] + data["margin"]),
                       fontsize=10, ha='center')
            
            ax.set_ylabel(title, fontsize=11)
            ax.set_title(f'{title}\n(n={data["n"]} runs)', fontsize=12, fontweight='bold')
            ax.set_xlim(-0.5, 0.8)
        
        plt.suptitle('95% Confidence Intervals Across Evaluation Runs', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/confidence_intervals.png", dpi=150)
        plt.close()
        print("   ✓ confidence_intervals.png")
    
    def plot_variance_across_runs(self):
        """Plot variance analysis across runs"""
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        
        runs = list(range(1, len(self.run_data) + 1))
        
        # Latency variance
        latencies = [r["latency"]["mean"] for r in self.run_data]
        ax1 = axes[0]
        ax1.plot(runs, latencies, 'o-', color='steelblue', linewidth=2, markersize=8)
        ax1.fill_between(runs, 
                         [l - r["latency"]["stdev"] for l, r in zip(latencies, self.run_data)],
                         [l + r["latency"]["stdev"] for l, r in zip(latencies, self.run_data)],
                         alpha=0.3, color='steelblue')
        ax1.axhline(statistics.mean(latencies), color='red', linestyle='--', label='Mean')
        ax1.set_xlabel('Run', fontsize=11)
        ax1.set_ylabel('Mean Latency (ms)', fontsize=11)
        ax1.set_title('Latency Variance Across Runs', fontsize=12, fontweight='bold')
        ax1.legend()
        
        # Throughput variance
        throughputs = [r["throughput"] for r in self.run_data]
        ax2 = axes[1]
        ax2.plot(runs, throughputs, 'o-', color='green', linewidth=2, markersize=8)
        ax2.axhline(statistics.mean(throughputs), color='red', linestyle='--', label='Mean')
        ax2.fill_between(runs, 
                         [t * 0.95 for t in throughputs],
                         [t * 1.05 for t in throughputs],
                         alpha=0.3, color='green')
        ax2.set_xlabel('Run', fontsize=11)
        ax2.set_ylabel('Throughput (msg/s)', fontsize=11)
        ax2.set_title('Throughput Variance Across Runs', fontsize=12, fontweight='bold')
        ax2.legend()
        
        # Accuracy variance
        accuracies = [r["accuracy"] for r in self.run_data]
        ax3 = axes[2]
        ax3.plot(runs, accuracies, 'o-', color='orange', linewidth=2, markersize=8)
        ax3.axhline(statistics.mean(accuracies), color='red', linestyle='--', label='Mean')
        ax3.set_xlabel('Run', fontsize=11)
        ax3.set_ylabel('Accuracy (%)', fontsize=11)
        ax3.set_title('Detection Accuracy Across Runs', fontsize=12, fontweight='bold')
        ax3.set_ylim([min(accuracies) - 5, 105])
        ax3.legend()
        
        plt.suptitle('Variance Analysis Across Evaluation Runs', fontsize=14, fontweight='bold')
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/variance_across_runs.png", dpi=150)
        plt.close()
        print("   ✓ variance_across_runs.png")
    
    def plot_throughput_analysis(self):
        """Plot throughput over time"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        runs = list(range(1, len(self.run_data) + 1))
        throughputs = [r["throughput"] for r in self.run_data]
        
        bars = ax.bar(runs, throughputs, color='teal', alpha=0.7, edgecolor='white')
        
        # Add mean line
        mean_throughput = statistics.mean(throughputs)
        ax.axhline(mean_throughput, color='red', linestyle='--', linewidth=2, 
                   label=f'Mean: {mean_throughput:.0f} msg/s')
        
        # Add value labels
        for bar, val in zip(bars, throughputs):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                   f'{val:.0f}', ha='center', fontsize=10)
        
        ax.set_xlabel('Evaluation Run', fontsize=12)
        ax.set_ylabel('Throughput (messages/second)', fontsize=12)
        ax.set_title('System Throughput Analysis', fontsize=14, fontweight='bold')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/throughput_analysis.png", dpi=150)
        plt.close()
        print("   ✓ throughput_analysis.png")
    
    def plot_confusion_matrix(self, classification: Dict):
        """Plot confusion matrix heatmap"""
        fig, ax = plt.subplots(figsize=(8, 6))
        
        cm = classification["confusion_matrix"]
        matrix = np.array([[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]])
        
        im = ax.imshow(matrix, cmap='Blues')
        
        # Add labels
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(['Predicted\nBenign', 'Predicted\nAttack'])
        ax.set_yticklabels(['Actual\nBenign', 'Actual\nAttack'])
        
        # Add values
        for i in range(2):
            for j in range(2):
                text = ax.text(j, i, matrix[i, j], ha="center", va="center", 
                              color="white" if matrix[i, j] > matrix.max()/2 else "black",
                              fontsize=16, fontweight='bold')
        
        ax.set_title('Confusion Matrix', fontsize=14, fontweight='bold')
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Count', fontsize=11)
        
        # Add metrics annotation
        metrics_text = f"Precision: {classification['precision']:.1f}%\nRecall: {classification['recall']:.1f}%\nF1-Score: {classification['f1_score']:.1f}%"
        ax.text(1.5, 0.5, metrics_text, transform=ax.transAxes, fontsize=11,
               verticalalignment='center', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
        
        plt.tight_layout()
        plt.savefig(f"{OUTPUT_DIR}/confusion_matrix.png", dpi=150)
        plt.close()
        print("   ✓ confusion_matrix.png")
    
    def plot_performance_dashboard(self, ci: Dict, classification: Dict):
        """Generate combined performance dashboard"""
        fig = plt.figure(figsize=(16, 12))
        
        # Create grid
        gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
        
        # 1. Latency distribution (top left)
        ax1 = fig.add_subplot(gs[0, 0])
        all_latencies = [l for run in self.latency_samples for l in run]
        ax1.hist(all_latencies, bins=30, color='steelblue', alpha=0.7, edgecolor='white')
        p95 = sorted(all_latencies)[int(len(all_latencies) * 0.95)]
        ax1.axvline(p95, color='red', linestyle='--', label=f'P95: {p95:.2f}ms')
        ax1.set_xlabel('Latency (ms)')
        ax1.set_ylabel('Frequency')
        ax1.set_title('Latency Distribution')
        ax1.legend()
        
        # 2. Throughput over runs (top middle)
        ax2 = fig.add_subplot(gs[0, 1])
        runs = list(range(1, len(self.run_data) + 1))
        throughputs = [r["throughput"] for r in self.run_data]
        ax2.plot(runs, throughputs, 'o-', color='green', linewidth=2)
        ax2.fill_between(runs, [t*0.95 for t in throughputs], [t*1.05 for t in throughputs], alpha=0.3)
        ax2.set_xlabel('Run')
        ax2.set_ylabel('Throughput (msg/s)')
        ax2.set_title('Throughput Over Runs')
        
        # 3. Classification metrics (top right)
        ax3 = fig.add_subplot(gs[0, 2])
        metrics = ['Precision', 'Recall', 'F1-Score', 'Accuracy']
        values = [classification['precision'], classification['recall'], 
                  classification['f1_score'], classification['accuracy']]
        colors = ['#2ecc71', '#3498db', '#9b59b6', '#e74c3c']
        bars = ax3.barh(metrics, values, color=colors, alpha=0.8)
        ax3.set_xlim([0, 105])
        ax3.set_xlabel('Percentage (%)')
        ax3.set_title('Classification Metrics')
        for bar, val in zip(bars, values):
            ax3.text(val + 1, bar.get_y() + bar.get_height()/2, f'{val:.1f}%', va='center')
        
        # 4. Variance analysis (middle row)
        ax4 = fig.add_subplot(gs[1, :])
        x = np.arange(len(self.run_data))
        width = 0.25
        latencies = [r["latency"]["mean"] for r in self.run_data]
        accuracies = [r["accuracy"] for r in self.run_data]
        
        # Normalize for comparison
        lat_norm = [l / max(latencies) * 100 for l in latencies]
        thr_norm = [t / max(throughputs) * 100 for t in throughputs]
        
        ax4.bar(x - width, lat_norm, width, label='Latency (normalized)', color='steelblue', alpha=0.7)
        ax4.bar(x, thr_norm, width, label='Throughput (normalized)', color='green', alpha=0.7)
        ax4.bar(x + width, accuracies, width, label='Accuracy (%)', color='orange', alpha=0.7)
        ax4.set_xlabel('Evaluation Run')
        ax4.set_ylabel('Normalized Value / Percentage')
        ax4.set_title('Normalized Performance Metrics Across Runs')
        ax4.set_xticks(x)
        ax4.set_xticklabels([f'Run {i+1}' for i in range(len(self.run_data))])
        ax4.legend()
        
        # 5. Confidence intervals (bottom left)
        ax5 = fig.add_subplot(gs[2, 0:2])
        ci_metrics = ['Latency\n(ms)', 'Throughput\n(msg/s)', 'Accuracy\n(%)']
        ci_values = [ci['latency_mean']['mean'], ci['throughput']['mean'], ci['accuracy']['mean']]
        ci_errors = [
            [ci['latency_mean']['mean'] - ci['latency_mean']['ci_lower'], 
             ci['latency_mean']['ci_upper'] - ci['latency_mean']['mean']],
            [ci['throughput']['mean'] - ci['throughput']['ci_lower'],
             ci['throughput']['ci_upper'] - ci['throughput']['mean']],
            [ci['accuracy']['mean'] - ci['accuracy']['ci_lower'],
             ci['accuracy']['ci_upper'] - ci['accuracy']['mean']]
        ]
        
        # Normalize for display
        ci_norm = [v / max(ci_values) * 100 for v in ci_values]
        ci_err_norm = [[e[0] / max(ci_values) * 100, e[1] / max(ci_values) * 100] for e in ci_errors]
        
        bars = ax5.bar(ci_metrics, ci_norm, color=['steelblue', 'green', 'orange'], alpha=0.7)
        ax5.errorbar(ci_metrics, ci_norm, 
                     yerr=[[e[0] for e in ci_err_norm], [e[1] for e in ci_err_norm]],
                     fmt='none', color='black', capsize=8, capthick=2)
        ax5.set_ylabel('Normalized Value')
        ax5.set_title('95% Confidence Intervals (Normalized)')
        
        # Add actual values
        for bar, val, orig in zip(bars, ci_norm, ci_values):
            ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                    f'{orig:.2f}', ha='center', fontsize=10)
        
        # 6. Summary stats (bottom right)
        ax6 = fig.add_subplot(gs[2, 2])
        ax6.axis('off')
        
        summary_text = f"""
        EVALUATION SUMMARY
        ══════════════════════
        
        Total Messages: {self.num_runs * self.messages_per_run:,}
        Evaluation Runs: {self.num_runs}
        
        ─── Latency ───
        Mean: {ci['latency_mean']['mean']:.2f} ms
        P95: {ci['latency_p95']['mean']:.2f} ms
        95% CI: [{ci['latency_mean']['ci_lower']:.2f}, {ci['latency_mean']['ci_upper']:.2f}]
        
        ─── Throughput ───
        Mean: {ci['throughput']['mean']:.0f} msg/s
        95% CI: [{ci['throughput']['ci_lower']:.0f}, {ci['throughput']['ci_upper']:.0f}]
        
        ─── Detection ───
        Accuracy: {classification['accuracy']:.1f}%
        F1-Score: {classification['f1_score']:.1f}%
        FPR: {classification['fpr']:.2f}%
        """
        
        ax6.text(0.1, 0.95, summary_text, transform=ax6.transAxes, fontsize=11,
                verticalalignment='top', fontfamily='monospace',
                bbox=dict(boxstyle='round', facecolor='lightgray', alpha=0.3))
        
        plt.suptitle('Vehicle Security System - Performance Evaluation Dashboard', 
                    fontsize=16, fontweight='bold')
        plt.savefig(f"{OUTPUT_DIR}/performance_dashboard.png", dpi=150, bbox_inches='tight')
        plt.close()
        print("   ✓ performance_dashboard.png")
    
    def print_evaluation_summary(self, ci: Dict, classification: Dict):
        """Print evaluation summary"""
        print("\n" + "=" * 70)
        print("📊 EVALUATION RESULTS SUMMARY")
        print("=" * 70)
        
        print("\n🕐 LATENCY METRICS (95% Confidence Interval)")
        print("-" * 50)
        print(f"   Mean Latency:  {ci['latency_mean']['mean']:.3f} ms")
        print(f"   95% CI:        [{ci['latency_mean']['ci_lower']:.3f}, {ci['latency_mean']['ci_upper']:.3f}] ms")
        print(f"   P95 Latency:   {ci['latency_p95']['mean']:.3f} ms")
        print(f"   Std Dev:       {ci['latency_mean']['stdev']:.3f} ms")
        
        print("\n📈 THROUGHPUT METRICS (95% Confidence Interval)")
        print("-" * 50)
        print(f"   Mean:          {ci['throughput']['mean']:.0f} msg/sec")
        print(f"   95% CI:        [{ci['throughput']['ci_lower']:.0f}, {ci['throughput']['ci_upper']:.0f}] msg/sec")
        print(f"   Std Dev:       {ci['throughput']['stdev']:.0f} msg/sec")
        
        print("\n🎯 CLASSIFICATION METRICS")
        print("-" * 50)
        cm = classification['confusion_matrix']
        print(f"   Confusion Matrix:")
        print(f"                    Predicted Attack  Predicted Benign")
        print(f"   Actual Attack         {cm['TP']:>5}              {cm['FN']:>5}")
        print(f"   Actual Benign         {cm['FP']:>5}              {cm['TN']:>5}")
        print()
        print(f"   Precision:       {classification['precision']:.2f}%")
        print(f"   Recall (TPR):    {classification['recall']:.2f}%")
        print(f"   Specificity:     {classification['specificity']:.2f}%")
        print(f"   F1-Score:        {classification['f1_score']:.2f}%")
        print(f"   Accuracy:        {classification['accuracy']:.2f}%")
        print(f"   FPR:             {classification['fpr']:.2f}%")
        print(f"   FNR:             {classification['fnr']:.2f}%")
        
        print("\n📊 VARIANCE ANALYSIS")
        print("-" * 50)
        print(f"   Latency Variance:    {statistics.variance([r['latency']['mean'] for r in self.run_data]):.4f}")
        print(f"   Throughput Variance: {statistics.variance([r['throughput'] for r in self.run_data]):.4f}")
        print(f"   Accuracy Variance:   {statistics.variance([r['accuracy'] for r in self.run_data]):.4f}")
        
        print("\n" + "=" * 70)
        print(f"📁 Results saved to: {OUTPUT_DIR}/")
        print("=" * 70 + "\n")


def main():
    print("\n🔬 Vehicle Security Evaluation Suite")
    print("=" * 50)
    
    # Check for matplotlib
    if not MATPLOTLIB_AVAILABLE:
        print("❌ matplotlib required for graphs. Install with:")
        print("   pip install matplotlib numpy")
        return
    
    print("\nChoose evaluation mode:")
    print("1. Quick evaluation (3 runs, 500 messages each)")
    print("2. Standard evaluation (5 runs, 1000 messages each)")
    print("3. Comprehensive evaluation (10 runs, 2000 messages each)")
    print("4. Custom evaluation")
    
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        suite = EvaluationSuite(num_runs=3, messages_per_run=500)
    elif choice == "2":
        suite = EvaluationSuite(num_runs=5, messages_per_run=1000)
    elif choice == "3":
        suite = EvaluationSuite(num_runs=10, messages_per_run=2000)
    elif choice == "4":
        runs = int(input("Number of runs: ") or "5")
        messages = int(input("Messages per run: ") or "1000")
        suite = EvaluationSuite(num_runs=runs, messages_per_run=messages)
    else:
        suite = EvaluationSuite(num_runs=5, messages_per_run=1000)
    
    suite.run_full_evaluation()


if __name__ == "__main__":
    main()
