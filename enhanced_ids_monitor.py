from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import pandas as pd
import threading
import queue
import time
import logging
from collections import defaultdict, deque
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import json
import hashlib

class EnhancedIDSMonitor:
    def __init__(self, model_path='trained_model.joblib'):
        self.packet_queue = queue.Queue(maxsize=10000)  # Limit queue size
        self.stop_flag = threading.Event()
        self.setup_logging()
        
        # Statistics and monitoring data
        self.stats = {
            'total_packets': 0,
            'intrusions_detected': 0,
            'anomalies_detected': 0,
            'suspicious_ips': set(),
            'port_scan_attempts': 0,
            'ddos_attempts': 0,
            'malicious_payloads': 0
        }
        
        # Network flow tracking with limited size
        self.flows = {}
        self.max_flows = 1000  # Limit number of flows to prevent memory issues
        
        # Anomaly detection with limited history
        self.packet_sizes = deque(maxlen=100)  # Reduced from 1000
        self.packet_intervals = deque(maxlen=100)
        
        # Load ML model
        try:
            self.model = joblib.load(model_path)
            logging.info("Loaded existing model")
        except FileNotFoundError:
            logging.warning("Creating default anomaly detection model")
            self.model = IsolationForest(contamination=0.1, random_state=42)
        
        # Alert history with limited size
        self.alerts = deque(maxlen=50)  # Reduced from 100
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='enhanced_ids.log'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(console_handler)

    def packet_callback(self, packet):
        """Enhanced packet analysis callback with error handling"""
        try:
            if self.packet_queue.qsize() < 9000:  # Prevent queue overflow
                timestamp = datetime.now()
                packet_info = self.extract_detailed_features(packet)
                self.packet_queue.put((timestamp, packet_info), timeout=0.1)
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def extract_detailed_features(self, packet):
        """Extract comprehensive features from packet with safety checks"""
        features = {
            'timestamp': datetime.now(),
            'protocol': 0,
            'packet_size': len(packet),
            'flags': 0,
            'header_length': 0,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'payload_size': 0,
            'is_fragment': False,
            'ttl': 0,
            'window_size': 0
        }
        
        try:
            if IP in packet:
                features['src_ip'] = str(packet[IP].src)
                features['dst_ip'] = str(packet[IP].dst)
                features['ttl'] = int(packet[IP].ttl)
                features['protocol'] = int(packet[IP].proto)
                features['is_fragment'] = bool(packet[IP].frag != 0)
                
            if TCP in packet:
                features['src_port'] = int(packet[TCP].sport)
                features['dst_port'] = int(packet[TCP].dport)
                features['flags'] = int(packet[TCP].flags)
                features['header_length'] = int(packet[TCP].dataofs)
                features['window_size'] = int(packet[TCP].window)
                features['payload_size'] = len(packet[TCP].payload)
                
            elif UDP in packet:
                features['src_port'] = int(packet[UDP].sport)
                features['dst_port'] = int(packet[UDP].dport)
                features['payload_size'] = len(packet[UDP].payload)
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
            
        return features

    def detect_anomalies(self, packet_info):
        """Detect various types of anomalies with safety checks"""
        anomalies = []
        
        try:
            # Packet size anomaly
            if packet_info['packet_size'] > 0:
                self.packet_sizes.append(packet_info['packet_size'])
                if len(self.packet_sizes) > 10:
                    mean_size = np.mean(list(self.packet_sizes))
                    std_size = np.std(list(self.packet_sizes))
                    if std_size > 0 and abs(packet_info['packet_size'] - mean_size) > 2 * std_size:
                        anomalies.append('unusual_packet_size')
            
            # Port scan detection
            if packet_info['src_ip'] and packet_info['dst_ip'] and packet_info['dst_port']:
                flow_key = f"{packet_info['src_ip']}_{packet_info['dst_ip']}"
                if flow_key in self.flows:
                    if 'ports' not in self.flows[flow_key]:
                        self.flows[flow_key]['ports'] = set()
                    self.flows[flow_key]['ports'].add(packet_info['dst_port'])
                    if len(self.flows[flow_key]['ports']) > 10:
                        anomalies.append('port_scan')
                        self.stats['port_scan_attempts'] += 1
            
            # DDoS detection
            if packet_info['src_ip']:
                src_flows = [f for f in self.flows.keys() if f.startswith(packet_info['src_ip'])]
                if len(src_flows) > 50:
                    anomalies.append('ddos_attempt')
                    self.stats['ddos_attempts'] += 1
            
            # Suspicious ports
            suspicious_ports = {22, 23, 3389, 445, 135, 139}
            if packet_info['dst_port'] in suspicious_ports:
                anomalies.append('suspicious_port_access')
                if packet_info['src_ip']:
                    self.stats['suspicious_ips'].add(packet_info['src_ip'])
                    
        except Exception as e:
            logging.error(f"Error in anomaly detection: {str(e)}")
        
        return anomalies

    def analyze_traffic(self):
        """Enhanced traffic analysis with recursion prevention"""
        while not self.stop_flag.is_set():
            try:
                if not self.packet_queue.empty():
                    timestamp, packet_info = self.packet_queue.get(timeout=0.1)
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    
                    # Update flow tracking with size limits
                    if packet_info['src_ip'] and packet_info['dst_ip']:
                        flow_key = f"{packet_info['src_ip']}_{packet_info['dst_ip']}"
                        
                        # Limit number of flows
                        if len(self.flows) >= self.max_flows and flow_key not in self.flows:
                            # Remove oldest flow
                            oldest_key = next(iter(self.flows))
                            del self.flows[oldest_key]
                        
                        if flow_key not in self.flows:
                            self.flows[flow_key] = {
                                'packet_count': 0,
                                'byte_count': 0,
                                'start_time': timestamp,
                                'last_seen': timestamp,
                                'flags': set(),
                                'ports': set()
                            }
                        
                        self.flows[flow_key]['packet_count'] += 1
                        self.flows[flow_key]['byte_count'] += packet_info['packet_size']
                        self.flows[flow_key]['last_seen'] = timestamp
                        
                        if packet_info['dst_port']:
                            self.flows[flow_key]['ports'].add(packet_info['dst_port'])
                    
                    # Detect anomalies
                    anomalies = self.detect_anomalies(packet_info)
                    
                    # ML-based intrusion detection
                    try:
                        features = np.array([[
                            packet_info['protocol'],
                            packet_info['packet_size'],
                            packet_info['flags'],
                            packet_info['header_length'],
                            packet_info['payload_size'],
                            packet_info['ttl']
                        ]])
                        
                        prediction = self.model.predict(features)[0]
                        if prediction == -1:  # Anomaly detected
                            anomalies.append('ml_anomaly')
                            self.stats['anomalies_detected'] += 1
                    except Exception as e:
                        logging.error(f"Error in ML prediction: {str(e)}")
                    
                    # Create alerts for detected issues
                    if anomalies:
                        alert = {
                            'timestamp': timestamp.isoformat(),
                            'src_ip': packet_info['src_ip'],
                            'dst_ip': packet_info['dst_ip'],
                            'anomalies': anomalies,
                            'packet_size': packet_info['packet_size'],
                            'protocol': packet_info['protocol']
                        }
                        self.alerts.append(alert)
                        self.stats['intrusions_detected'] += 1
                        
                        logging.warning(f"Alert: {anomalies} from {packet_info['src_ip']} to {packet_info['dst_ip']}")
                    
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in analysis: {str(e)}")
            
            time.sleep(0.001)

    def get_dashboard_data(self):
        """Get comprehensive dashboard data with safety checks"""
        try:
            # Convert sets to lists for JSON serialization
            suspicious_ips_list = list(self.stats['suspicious_ips'])[-10:]
            
            # Convert flows to serializable format
            flows_list = []
            for k, v in list(self.flows.items())[-10:]:
                flows_list.append([
                    k,
                    {
                        'packet_count': v['packet_count'],
                        'byte_count': v['byte_count'],
                        'ports': list(v.get('ports', []))
                    }
                ])
            
            return {
                'statistics': {
                    'total_packets': self.stats['total_packets'],
                    'intrusions_detected': self.stats['intrusions_detected'],
                    'anomalies_detected': self.stats['anomalies_detected'],
                    'port_scan_attempts': self.stats['port_scan_attempts'],
                    'ddos_attempts': self.stats['ddos_attempts'],
                    'suspicious_ips_count': len(self.stats['suspicious_ips']),
                    'active_flows': len(self.flows)
                },
                'recent_alerts': list(self.alerts)[-10:],
                'suspicious_ips': suspicious_ips_list,
                'top_flows': flows_list,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error getting dashboard data: {str(e)}")
            return {
                'statistics': {'total_packets': 0, 'intrusions_detected': 0, 'anomalies_detected': 0, 'port_scan_attempts': 0, 'ddos_attempts': 0, 'suspicious_ips_count': 0, 'active_flows': 0},
                'recent_alerts': [],
                'suspicious_ips': [],
                'top_flows': [],
                'timestamp': datetime.now().isoformat()
            }

    def start_monitoring(self):
        """Start the enhanced monitoring process"""
        logging.info("Starting enhanced IDS monitoring...")
        
        try:
            # Test packet capture
            test_capture = sniff(count=1, timeout=2)
            if not test_capture:
                logging.warning("No packets captured in test. Please ensure Npcap is installed.")
                return None, None
        except Exception as e:
            logging.error(f"Error during packet capture test: {str(e)}")
            return None, None

        # Start threads
        capture_thread = threading.Thread(target=lambda: sniff(
            prn=self.packet_callback,
            store=0,
            stop_filter=lambda _: self.stop_flag.is_set()
        ))
        
        analysis_thread = threading.Thread(target=self.analyze_traffic)
        
        capture_thread.start()
        analysis_thread.start()
        
        return capture_thread, analysis_thread

    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.stop_flag.set()
        logging.info("Stopping enhanced IDS monitoring...")
        logging.info(f"Final Statistics: {self.stats}")

if __name__ == "__main__":
    monitor = EnhancedIDSMonitor()
    try:
        capture_thread, analysis_thread = monitor.start_monitoring()
        
        while True:
            time.sleep(1)
            data = monitor.get_dashboard_data()
            print(f"\n=== IDS Dashboard Update ===")
            print(f"Packets: {data['statistics']['total_packets']}")
            print(f"Intrusions: {data['statistics']['intrusions_detected']}")
            print(f"Anomalies: {data['statistics']['anomalies_detected']}")
            print(f"Active Flows: {data['statistics']['active_flows']}")
            
    except KeyboardInterrupt:
        print("\nStopping enhanced IDS monitoring...")
        monitor.stop_monitoring()
        if capture_thread:
            capture_thread.join()
        if analysis_thread:
            analysis_thread.join() 