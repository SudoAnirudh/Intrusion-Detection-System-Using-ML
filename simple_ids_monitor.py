from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import threading
import queue
import time
import logging
from collections import deque
import numpy as np

class SimpleIDSMonitor:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=1000)
        self.stop_flag = threading.Event()
        self.setup_logging()
        
        # Simple statistics
        self.stats = {
            'total_packets': 0,
            'intrusions_detected': 0,
            'anomalies_detected': 0,
            'port_scan_attempts': 0,
            'ddos_attempts': 0,
            'suspicious_ips': []
        }
        
        # Simple flow tracking
        self.flows = {}
        self.max_flows = 100
        
        # Simple packet history
        self.packet_sizes = []
        self.max_history = 50
        
        # Simple alerts
        self.alerts = []
        self.max_alerts = 20
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='simple_ids.log'
        )
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(console_handler)

    def packet_callback(self, packet):
        """Simple packet callback"""
        try:
            if self.packet_queue.qsize() < 900:
                packet_info = self.extract_simple_features(packet)
                self.packet_queue.put(packet_info, timeout=0.1)
        except Exception as e:
            logging.error(f"Error in packet callback: {str(e)}")

    def extract_simple_features(self, packet):
        """Extract basic features without complex operations"""
        features = {
            'packet_size': len(packet),
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': 0
        }
        
        try:
            if IP in packet:
                features['src_ip'] = str(packet[IP].src)
                features['dst_ip'] = str(packet[IP].dst)
                features['protocol'] = int(packet[IP].proto)
                
            if TCP in packet:
                features['src_port'] = int(packet[TCP].sport)
                features['dst_port'] = int(packet[TCP].dport)
            elif UDP in packet:
                features['src_port'] = int(packet[UDP].sport)
                features['dst_port'] = int(packet[UDP].dport)
                
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
            
        return features

    def detect_simple_anomalies(self, packet_info):
        """Simple anomaly detection"""
        anomalies = []
        
        try:
            # Packet size anomaly
            if packet_info['packet_size'] > 0:
                self.packet_sizes.append(packet_info['packet_size'])
                if len(self.packet_sizes) > self.max_history:
                    self.packet_sizes.pop(0)
                
                if len(self.packet_sizes) > 10:
                    mean_size = sum(self.packet_sizes) / len(self.packet_sizes)
                    if abs(packet_info['packet_size'] - mean_size) > mean_size * 2:
                        anomalies.append('unusual_packet_size')
            
            # Port scan detection
            if packet_info['src_ip'] and packet_info['dst_ip'] and packet_info['dst_port']:
                flow_key = f"{packet_info['src_ip']}_{packet_info['dst_ip']}"
                
                if flow_key not in self.flows:
                    if len(self.flows) >= self.max_flows:
                        # Remove oldest flow
                        oldest_key = list(self.flows.keys())[0]
                        del self.flows[oldest_key]
                    
                    self.flows[flow_key] = {
                        'packet_count': 0,
                        'ports': []
                    }
                
                self.flows[flow_key]['packet_count'] += 1
                if packet_info['dst_port'] not in self.flows[flow_key]['ports']:
                    self.flows[flow_key]['ports'].append(packet_info['dst_port'])
                
                if len(self.flows[flow_key]['ports']) > 10:
                    anomalies.append('port_scan')
                    self.stats['port_scan_attempts'] += 1
            
            # DDoS detection
            if packet_info['src_ip']:
                src_flows = [f for f in self.flows.keys() if f.startswith(packet_info['src_ip'])]
                if len(src_flows) > 20:
                    anomalies.append('ddos_attempt')
                    self.stats['ddos_attempts'] += 1
            
            # Suspicious ports
            suspicious_ports = [22, 23, 3389, 445, 135, 139]
            if packet_info['dst_port'] in suspicious_ports:
                anomalies.append('suspicious_port_access')
                if packet_info['src_ip'] and packet_info['src_ip'] not in self.stats['suspicious_ips']:
                    self.stats['suspicious_ips'].append(packet_info['src_ip'])
                    if len(self.stats['suspicious_ips']) > 20:
                        self.stats['suspicious_ips'].pop(0)
                        
        except Exception as e:
            logging.error(f"Error in anomaly detection: {str(e)}")
        
        return anomalies

    def analyze_traffic(self):
        """Simple traffic analysis"""
        while not self.stop_flag.is_set():
            try:
                if not self.packet_queue.empty():
                    packet_info = self.packet_queue.get(timeout=0.1)
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    
                    # Detect anomalies
                    anomalies = self.detect_simple_anomalies(packet_info)
                    
                    # Create alerts
                    if anomalies:
                        alert = {
                            'timestamp': datetime.now().isoformat(),
                            'src_ip': packet_info['src_ip'],
                            'dst_ip': packet_info['dst_ip'],
                            'anomalies': anomalies,
                            'packet_size': packet_info['packet_size']
                        }
                        
                        self.alerts.append(alert)
                        if len(self.alerts) > self.max_alerts:
                            self.alerts.pop(0)
                        
                        self.stats['intrusions_detected'] += 1
                        logging.warning(f"Alert: {anomalies} from {packet_info['src_ip']} to {packet_info['dst_ip']}")
                    
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in analysis: {str(e)}")
            
            time.sleep(0.001)

    def get_dashboard_data(self):
        """Get simple dashboard data"""
        try:
            # Get top flows
            flows_list = []
            for k, v in list(self.flows.items())[-10:]:
                flows_list.append([
                    k,
                    {
                        'packet_count': v['packet_count'],
                        'ports': v['ports']
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
                'recent_alerts': self.alerts[-10:],
                'suspicious_ips': self.stats['suspicious_ips'][-10:],
                'top_flows': flows_list,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error getting dashboard data: {str(e)}")
            return {
                'statistics': {
                    'total_packets': 0,
                    'intrusions_detected': 0,
                    'anomalies_detected': 0,
                    'port_scan_attempts': 0,
                    'ddos_attempts': 0,
                    'suspicious_ips_count': 0,
                    'active_flows': 0
                },
                'recent_alerts': [],
                'suspicious_ips': [],
                'top_flows': [],
                'timestamp': datetime.now().isoformat()
            }

    def start_monitoring(self):
        """Start simple monitoring"""
        logging.info("Starting simple IDS monitoring...")
        
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
        """Stop monitoring"""
        self.stop_flag.set()
        logging.info("Stopping simple IDS monitoring...")
        logging.info(f"Final Statistics: {self.stats}")

if __name__ == "__main__":
    monitor = SimpleIDSMonitor()
    try:
        capture_thread, analysis_thread = monitor.start_monitoring()
        
        while True:
            time.sleep(1)
            data = monitor.get_dashboard_data()
            print(f"\n=== Simple IDS Dashboard Update ===")
            print(f"Packets: {data['statistics']['total_packets']}")
            print(f"Intrusions: {data['statistics']['intrusions_detected']}")
            print(f"Active Flows: {data['statistics']['active_flows']}")
            
    except KeyboardInterrupt:
        print("\nStopping simple IDS monitoring...")
        monitor.stop_monitoring()
        if capture_thread:
            capture_thread.join()
        if analysis_thread:
            analysis_thread.join() 