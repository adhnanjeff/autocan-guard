"""
Kafka Message Viewer
Real-time display of Kafka messages with filtering and formatting
Perfect for demonstrations and debugging
"""

import json
import time
import argparse
import sys
from datetime import datetime
from collections import defaultdict

# Fix namespace conflict with local kafka/ directory
try:
    from kafka import KafkaConsumer
except ImportError:
    print("❌ kafka-python not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "kafka-python==2.0.2"])
    from kafka import KafkaConsumer

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class KafkaMessageViewer:
    def __init__(self, vehicle_id="vehicleA", topics=None, bootstrap_server='localhost:9092', 
                 max_messages=None, show_keys=True, show_timestamps=True):
        self.vehicle_id = vehicle_id
        self.bootstrap_server = bootstrap_server
        self.max_messages = max_messages
        self.show_keys = show_keys
        self.show_timestamps = show_timestamps
        
        # Setup topics
        if topics:
            self.topics = topics
        else:
            # Default: subscribe to all vehicle topics
            self.topics = [
                f'vehicle.{vehicle_id}.telemetry',
                f'vehicle.{vehicle_id}.security',
                'alerts.system'
            ]
        
        # Statistics
        self.message_count = defaultdict(int)
        self.total_messages = 0
        self.start_time = time.time()
        
        self.consumer = None
        self._setup_consumer()
    
    def _setup_consumer(self):
        """Setup Kafka consumer"""
        try:
            self.consumer = KafkaConsumer(
                *self.topics,
                bootstrap_servers=[self.bootstrap_server],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')) if m else None,
                key_deserializer=lambda k: k.decode('utf-8') if k else None,
                auto_offset_reset='latest',  # Only show new messages
                enable_auto_commit=True,
                # No timeout - run continuously until Ctrl+C
            )
            print(f"{Colors.OKGREEN}✅ Connected to Kafka at {self.bootstrap_server}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}📡 Subscribed to topics: {', '.join(self.topics)}{Colors.ENDC}")
            print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}\n")
            
        except Exception as e:
            print(f"{Colors.FAIL}❌ Failed to connect to Kafka: {e}{Colors.ENDC}")
            self.consumer = None
    
    def _format_message(self, message):
        """Format message for display"""
        topic = message.topic
        key = message.key if self.show_keys else None
        value = message.value
        timestamp = datetime.fromtimestamp(message.timestamp / 1000) if self.show_timestamps else None
        
        # Color based on topic
        if 'telemetry' in topic:
            color = Colors.OKBLUE
            emoji = "📊"
        elif 'security' in topic:
            color = Colors.WARNING
            emoji = "🔒"
        elif 'alerts' in topic:
            color = Colors.FAIL
            emoji = "🚨"
        else:
            color = Colors.ENDC
            emoji = "📨"
        
        # Build output
        output = []
        output.append(f"{color}{Colors.BOLD}{emoji} [{topic}]{Colors.ENDC}")
        
        if self.show_timestamps:
            output.append(f"{Colors.OKCYAN}⏰ Time: {timestamp.strftime('%H:%M:%S.%f')[:-3]}{Colors.ENDC}")
        
        if self.show_keys and key:
            output.append(f"{Colors.OKGREEN}🔑 Key: {key}{Colors.ENDC}")
        
        # Format value based on content
        if isinstance(value, dict):
            output.append(f"{color}📦 Message:{Colors.ENDC}")
            for k, v in value.items():
                # Highlight important fields
                if k in ['can_id', 'arb_id', 'vehicle_id', 'sender_id']:
                    output.append(f"  {Colors.BOLD}{k}{Colors.ENDC}: {v}")
                elif k in ['trust_score', 'anomaly_score']:
                    # Color code trust/anomaly scores
                    if k == 'trust_score':
                        score_color = Colors.OKGREEN if v > 0.7 else Colors.WARNING if v > 0.3 else Colors.FAIL
                    else:  # anomaly_score
                        score_color = Colors.FAIL if v > 0.5 else Colors.WARNING if v > 0.3 else Colors.OKGREEN
                    output.append(f"  {k}: {score_color}{v:.3f}{Colors.ENDC}")
                elif k in ['data', 'payload'] and isinstance(v, list):
                    output.append(f"  {k}: {' '.join(f'{b:02X}' for b in v[:8])}{'...' if len(v) > 8 else ''}")
                elif k in ['timestamp', 'event_time']:
                    # Show relative time
                    try:
                        msg_time = float(v)
                        rel_time = time.time() - msg_time
                        output.append(f"  {k}: {msg_time:.3f} ({rel_time:.2f}s ago)")
                    except:
                        output.append(f"  {k}: {v}")
                else:
                    output.append(f"  {k}: {v}")
        else:
            output.append(f"{color}{value}{Colors.ENDC}")
        
        return '\n'.join(output)
    
    def _print_statistics(self):
        """Print consumption statistics"""
        duration = time.time() - self.start_time
        rate = self.total_messages / duration if duration > 0 else 0
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}📈 Statistics:{Colors.ENDC}")
        print(f"  Total Messages: {self.total_messages}")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Rate: {rate:.2f} msg/s")
        print(f"\n  By Topic:")
        for topic, count in self.message_count.items():
            print(f"    {topic}: {count} messages")
        print(f"{Colors.BOLD}{'='*80}{Colors.ENDC}")
    
    def start(self):
        """Start consuming and displaying messages"""
        if not self.consumer:
            print(f"{Colors.FAIL}❌ Cannot start: consumer not initialized{Colors.ENDC}")
            return
        
        print(f"{Colors.OKGREEN}🚀 Starting message viewer...{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Press Ctrl+C to stop{Colors.ENDC}")
        print(f"{Colors.WARNING}⏳ Waiting for messages...{Colors.ENDC}\n")
        
        try:
            while True:
                # Poll for messages with timeout
                message_batch = self.consumer.poll(timeout_ms=1000, max_records=10)
                
                if not message_batch:
                    # No messages yet, continue waiting
                    continue
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        # Format and print message
                        formatted = self._format_message(message)
                        print(formatted)
                        print()  # Blank line between messages
                        
                        # Update statistics
                        self.message_count[message.topic] += 1
                        self.total_messages += 1
                        
                        # Check if we've reached max messages
                        if self.max_messages and self.total_messages >= self.max_messages:
                            print(f"{Colors.WARNING}Reached maximum message count: {self.max_messages}{Colors.ENDC}")
                            return
                
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}⏸️  Stopped by user{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}❌ Error: {e}{Colors.ENDC}")
        finally:
            self._print_statistics()
            if self.consumer:
                self.consumer.close()

def main():
    parser = argparse.ArgumentParser(description='Kafka Message Viewer - Real-time message display')
    parser.add_argument('--vehicle-id', default='vehicleA', help='Vehicle ID (default: vehicleA)')
    parser.add_argument('--topics', nargs='+', help='Specific topics to subscribe to')
    parser.add_argument('--broker', default='localhost:9092', help='Kafka broker (default: localhost:9092)')
    parser.add_argument('--max-messages', type=int, help='Stop after N messages')
    parser.add_argument('--no-keys', action='store_true', help='Hide message keys')
    parser.add_argument('--no-timestamps', action='store_true', help='Hide timestamps')
    
    args = parser.parse_args()
    
    viewer = KafkaMessageViewer(
        vehicle_id=args.vehicle_id,
        topics=args.topics,
        bootstrap_server=args.broker,
        max_messages=args.max_messages,
        show_keys=not args.no_keys,
        show_timestamps=not args.no_timestamps
    )
    
    viewer.start()

if __name__ == '__main__':
    main()
