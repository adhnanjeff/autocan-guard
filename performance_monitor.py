"""
Performance Monitoring System for Vehicle Security Platform
Tracks latency, throughput, processing time, and system metrics
"""

import time
import threading
import statistics
from datetime import datetime
from collections import deque
from typing import Dict, List, Any
import json
import os

# Try to import psutil, provide fallback if not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("⚠️ psutil not available - system metrics will be estimated")

class PerformanceMonitor:
    def __init__(self):
        self.running = False
        self.monitor_thread = None
        
        # Latency tracking (in milliseconds)
        self.message_latencies = deque(maxlen=10000)  # Last 10000 messages
        self.crypto_latencies = deque(maxlen=10000)   # Crypto operation times
        self.etl_latencies = deque(maxlen=1000)       # ETL batch processing times
        self.detection_latencies = deque(maxlen=10000) # Anomaly detection times
        
        # Throughput tracking
        self.messages_processed = 0
        self.messages_per_second = deque(maxlen=300)  # Last 5 minutes
        self.start_time = time.time()
        self.last_throughput_check = time.time()
        self.messages_in_interval = 0
        
        # Attack detection metrics
        self.true_positives = 0   # Correctly detected attacks
        self.true_negatives = 0   # Correctly accepted legitimate
        self.false_positives = 0  # Incorrectly rejected legitimate
        self.false_negatives = 0  # Missed attacks
        self.total_verifications = 0
        
        # System resource metrics
        self.cpu_usage = deque(maxlen=300)
        self.memory_usage = deque(maxlen=300)
        
        # Message type distribution
        self.message_types = {
            "speed": 0,
            "steering": 0,
            "brake": 0,
            "other": 0
        }
        
        # Per-run statistics for variance analysis
        self.run_results = []
        self.current_run = {
            "latencies": [],
            "throughputs": [],
            "detection_rates": []
        }
        
        print("📊 Performance Monitor initialized")
    
    def start_monitoring(self):
        """Start background performance monitoring"""
        if self.running:
            return
        
        self.running = True
        self.start_time = time.time()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("✅ Performance monitoring started")
    
    def _monitor_loop(self):
        """Background loop for system metrics"""
        while self.running:
            try:
                # Collect system metrics
                if PSUTIL_AVAILABLE:
                    self.cpu_usage.append(psutil.cpu_percent(interval=0.1))
                    self.memory_usage.append(psutil.virtual_memory().percent)
                else:
                    # Fallback estimation
                    self.cpu_usage.append(15.0 + (time.time() % 10))
                    self.memory_usage.append(45.0 + (time.time() % 5))
                
                # Calculate throughput
                current_time = time.time()
                if current_time - self.last_throughput_check >= 1.0:
                    throughput = self.messages_in_interval
                    self.messages_per_second.append(throughput)
                    self.current_run["throughputs"].append(throughput)
                    self.messages_in_interval = 0
                    self.last_throughput_check = current_time
                
                time.sleep(1.0)
            except Exception as e:
                print(f"❌ Monitor error: {e}")
    
    # ============ TRACKING METHODS ============
    
    def track_message_latency(self, latency_ms: float):
        """Track end-to-end message processing latency"""
        self.message_latencies.append(latency_ms)
        self.current_run["latencies"].append(latency_ms)
        self.messages_processed += 1
        self.messages_in_interval += 1
    
    def track_crypto_operation(self, operation_time_ms: float):
        """Track cryptographic operation time"""
        self.crypto_latencies.append(operation_time_ms)
    
    def track_detection_latency(self, detection_time_ms: float):
        """Track anomaly detection time"""
        self.detection_latencies.append(detection_time_ms)
    
    def track_etl_batch(self, batch_time_ms: float):
        """Track ETL batch processing time"""
        self.etl_latencies.append(batch_time_ms)
    
    def track_message_type(self, can_id: int):
        """Track message type distribution"""
        if can_id == 0x130:
            self.message_types["speed"] += 1
        elif can_id == 0x120:
            self.message_types["steering"] += 1
        elif can_id == 0x140:
            self.message_types["brake"] += 1
        else:
            self.message_types["other"] += 1
    
    def track_detection_result(self, predicted_attack: bool, actual_attack: bool):
        """
        Track detection result against ground truth
        Dt = 1 if attack detected, 0 if benign
        Ground truth: attack_traffic -> expected Dt = 1, benign -> expected Dt = 0
        """
        self.total_verifications += 1
        
        if predicted_attack and actual_attack:
            self.true_positives += 1  # Correctly detected attack
        elif not predicted_attack and not actual_attack:
            self.true_negatives += 1  # Correctly accepted benign
        elif predicted_attack and not actual_attack:
            self.false_positives += 1  # False alarm
        else:
            self.false_negatives += 1  # Missed attack
        
        # Track detection rate for this run
        if self.total_verifications > 0:
            current_detection_rate = self.true_positives / (self.true_positives + self.false_negatives) if (self.true_positives + self.false_negatives) > 0 else 1.0
            self.current_run["detection_rates"].append(current_detection_rate)
    
    def end_run(self):
        """End current evaluation run and store results"""
        if self.current_run["latencies"]:
            self.run_results.append({
                "avg_latency": statistics.mean(self.current_run["latencies"]),
                "p95_latency": sorted(self.current_run["latencies"])[int(len(self.current_run["latencies"]) * 0.95)] if len(self.current_run["latencies"]) > 20 else max(self.current_run["latencies"]),
                "avg_throughput": statistics.mean(self.current_run["throughputs"]) if self.current_run["throughputs"] else 0,
                "detection_rate": self.current_run["detection_rates"][-1] if self.current_run["detection_rates"] else 0,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Reset for next run
        self.current_run = {
            "latencies": [],
            "throughputs": [],
            "detection_rates": []
        }
    
    # ============ STATISTICS CALCULATION ============
    
    def get_latency_stats(self) -> Dict[str, float]:
        """Calculate latency statistics"""
        if not self.message_latencies:
            return {"min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0, "stdev": 0}
        
        sorted_latencies = sorted(self.message_latencies)
        n = len(sorted_latencies)
        
        return {
            "min": round(min(sorted_latencies), 3),
            "max": round(max(sorted_latencies), 3),
            "avg": round(statistics.mean(sorted_latencies), 3),
            "median": round(statistics.median(sorted_latencies), 3),
            "p50": round(sorted_latencies[int(n * 0.50)], 3),
            "p95": round(sorted_latencies[int(n * 0.95)], 3) if n > 20 else round(max(sorted_latencies), 3),
            "p99": round(sorted_latencies[int(n * 0.99)], 3) if n > 100 else round(max(sorted_latencies), 3),
            "stdev": round(statistics.stdev(sorted_latencies), 3) if n > 1 else 0
        }
    
    def get_crypto_stats(self) -> Dict[str, float]:
        """Calculate cryptographic operation statistics"""
        if not self.crypto_latencies:
            return {"min": 0, "max": 0, "avg": 0, "median": 0}
        
        return {
            "min": round(min(self.crypto_latencies), 3),
            "max": round(max(self.crypto_latencies), 3),
            "avg": round(statistics.mean(self.crypto_latencies), 3),
            "median": round(statistics.median(self.crypto_latencies), 3)
        }
    
    def get_throughput_stats(self) -> Dict[str, float]:
        """Calculate throughput statistics"""
        if not self.messages_per_second:
            return {"current": 0, "avg": 0, "peak": 0, "stdev": 0}
        
        mps_list = list(self.messages_per_second)
        return {
            "current": mps_list[-1] if mps_list else 0,
            "avg": round(statistics.mean(mps_list), 2),
            "peak": max(mps_list),
            "min": min(mps_list),
            "stdev": round(statistics.stdev(mps_list), 2) if len(mps_list) > 1 else 0,
            "total_messages": self.messages_processed,
            "uptime_seconds": round(time.time() - self.start_time, 2)
        }
    
    def get_system_stats(self) -> Dict[str, float]:
        """Get system resource usage"""
        return {
            "cpu_current": round(self.cpu_usage[-1], 1) if self.cpu_usage else 0,
            "cpu_avg": round(statistics.mean(self.cpu_usage), 1) if self.cpu_usage else 0,
            "cpu_stdev": round(statistics.stdev(self.cpu_usage), 1) if len(self.cpu_usage) > 1 else 0,
            "memory_current": round(self.memory_usage[-1], 1) if self.memory_usage else 0,
            "memory_avg": round(statistics.mean(self.memory_usage), 1) if self.memory_usage else 0
        }
    
    def get_classification_metrics(self) -> Dict[str, Any]:
        """
        Get classification performance metrics
        Based on confusion matrix: TP, TN, FP, FN
        """
        tp = self.true_positives
        tn = self.true_negatives
        fp = self.false_positives
        fn = self.false_negatives
        
        # Precision = TP / (TP + FP)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        
        # Recall (Sensitivity, True Positive Rate) = TP / (TP + FN)
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # Specificity (True Negative Rate) = TN / (TN + FP)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Accuracy = (TP + TN) / (TP + TN + FP + FN)
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0
        
        # False Positive Rate = FP / (FP + TN)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        # False Negative Rate = FN / (FN + TP)
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        return {
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn
            },
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "specificity": round(specificity * 100, 2),
            "f1_score": round(f1_score * 100, 2),
            "accuracy": round(accuracy * 100, 2),
            "false_positive_rate": round(fpr * 100, 2),
            "false_negative_rate": round(fnr * 100, 2),
            "total_samples": total
        }
    
    def get_latency_distribution(self) -> Dict[str, int]:
        """Get latency distribution for histogram"""
        if not self.message_latencies:
            return {}
        
        # Create buckets: <1ms, 1-5ms, 5-10ms, 10-50ms, 50-100ms, >100ms
        distribution = {
            "0-1ms": 0,
            "1-5ms": 0,
            "5-10ms": 0,
            "10-50ms": 0,
            "50-100ms": 0,
            ">100ms": 0
        }
        
        for latency in self.message_latencies:
            if latency < 1:
                distribution["0-1ms"] += 1
            elif latency < 5:
                distribution["1-5ms"] += 1
            elif latency < 10:
                distribution["5-10ms"] += 1
            elif latency < 50:
                distribution["10-50ms"] += 1
            elif latency < 100:
                distribution["50-100ms"] += 1
            else:
                distribution[">100ms"] += 1
        
        return distribution
    
    def get_variance_across_runs(self) -> Dict[str, Any]:
        """Calculate variance and confidence intervals across multiple runs"""
        if len(self.run_results) < 2:
            return {"message": "Need at least 2 runs for variance analysis"}
        
        latencies = [r["avg_latency"] for r in self.run_results]
        throughputs = [r["avg_throughput"] for r in self.run_results]
        detection_rates = [r["detection_rate"] for r in self.run_results]
        
        def confidence_interval(data, confidence=0.95):
            """Calculate 95% confidence interval"""
            n = len(data)
            mean = statistics.mean(data)
            stdev = statistics.stdev(data) if n > 1 else 0
            # t-value for 95% CI with n-1 degrees of freedom (approximation)
            t_value = 1.96 if n > 30 else 2.0
            margin = t_value * (stdev / (n ** 0.5))
            return {
                "mean": round(mean, 3),
                "stdev": round(stdev, 3),
                "ci_lower": round(mean - margin, 3),
                "ci_upper": round(mean + margin, 3),
                "margin_of_error": round(margin, 3)
            }
        
        return {
            "num_runs": len(self.run_results),
            "latency": confidence_interval(latencies),
            "throughput": confidence_interval(throughputs),
            "detection_rate": confidence_interval([d * 100 for d in detection_rates])  # Convert to percentage
        }
    
    # ============ REPORTING ============
    
    def generate_report(self, output_file: str = None) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": round(time.time() - self.start_time, 2),
            "latency_metrics": self.get_latency_stats(),
            "crypto_performance": self.get_crypto_stats(),
            "throughput_metrics": self.get_throughput_stats(),
            "system_resources": self.get_system_stats(),
            "classification_metrics": self.get_classification_metrics(),
            "latency_distribution": self.get_latency_distribution(),
            "message_type_distribution": self.message_types,
            "variance_analysis": self.get_variance_across_runs(),
            "etl_performance": {
                "avg_batch_time_ms": round(statistics.mean(self.etl_latencies), 3) if self.etl_latencies else 0,
                "total_batches": len(self.etl_latencies)
            }
        }
        
        if output_file:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"📄 Performance report saved to: {output_file}")
        
        return report
    
    def print_summary(self):
        """Print performance summary to console"""
        latency = self.get_latency_stats()
        throughput = self.get_throughput_stats()
        system = self.get_system_stats()
        classification = self.get_classification_metrics()
        distribution = self.get_latency_distribution()
        
        print("\n" + "=" * 70)
        print("📊 SYSTEM PERFORMANCE METRICS")
        print("=" * 70)
        
        print("\n🕐 LATENCY DISTRIBUTION")
        print("-" * 40)
        print(f"   • Average:       {latency['avg']:.2f} ms")
        print(f"   • Median (P50):  {latency['p50']:.2f} ms")
        print(f"   • P95:           {latency['p95']:.2f} ms")
        print(f"   • P99:           {latency['p99']:.2f} ms")
        print(f"   • Min/Max:       {latency['min']:.2f} / {latency['max']:.2f} ms")
        print(f"   • Std Dev:       {latency['stdev']:.2f} ms")
        
        print("\n   Histogram:")
        total = sum(distribution.values())
        for bucket, count in distribution.items():
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 2)
            print(f"   {bucket:>8}: {count:>5} ({pct:5.1f}%) {bar}")
        
        print("\n📈 THROUGHPUT")
        print("-" * 40)
        print(f"   • Current:       {throughput['current']:.0f} msg/sec")
        print(f"   • Average:       {throughput['avg']:.0f} msg/sec")
        print(f"   • Peak:          {throughput['peak']:.0f} msg/sec")
        print(f"   • Std Dev:       {throughput['stdev']:.0f} msg/sec")
        print(f"   • Total:         {throughput['total_messages']} messages")
        
        print("\n🎯 CLASSIFICATION METRICS (Evaluation)")
        print("-" * 40)
        cm = classification["confusion_matrix"]
        print(f"   Confusion Matrix:")
        print(f"                    Predicted")
        print(f"                  Attack  Benign")
        print(f"   Actual Attack    {cm['true_positives']:>4}    {cm['false_negatives']:>4}")
        print(f"   Actual Benign    {cm['false_positives']:>4}    {cm['true_negatives']:>4}")
        print()
        print(f"   • Precision:     {classification['precision']:.2f}%")
        print(f"   • Recall (TPR):  {classification['recall']:.2f}%")
        print(f"   • Specificity:   {classification['specificity']:.2f}%")
        print(f"   • F1-Score:      {classification['f1_score']:.2f}%")
        print(f"   • Accuracy:      {classification['accuracy']:.2f}%")
        print(f"   • FPR:           {classification['false_positive_rate']:.2f}%")
        print(f"   • FNR:           {classification['false_negative_rate']:.2f}%")
        
        print("\n💻 SYSTEM RESOURCES")
        print("-" * 40)
        print(f"   • CPU Usage:     {system['cpu_avg']:.1f}% (avg), ±{system['cpu_stdev']:.1f}%")
        print(f"   • Memory Usage:  {system['memory_avg']:.1f}% (avg)")
        
        print("=" * 70 + "\n")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
        print("🔌 Performance monitoring stopped")

# Global performance monitor instance
performance_monitor = PerformanceMonitor()
