from scapy.all import sniff
from datetime import datetime
import pandas as pd
import threading
import queue
import time
import logging
from collections import defaultdict
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class RealTimeMonitor:
    def __init__(self, model_path='trained_model.joblib'):
        self.packet_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.stats = defaultdict(int)
        self.setup_logging()
        
        try:
            self.model = joblib.load(model_path)
            logging.info("Loaded existing model from file")
        except FileNotFoundError:
            logging.warning(f"Model file {model_path} not found. Creating a basic default model.")
            # Create a simple default model
            self.model = RandomForestClassifier(n_estimators=100)
            # Train with some basic dummy data to initialize it
            X_dummy = np.random.rand(100, 4)  # 4 features
            y_dummy = np.random.randint(0, 2, 100)  # Binary classification
            self.model.fit(X_dummy, y_dummy)
            # Save the model for future use
            joblib.dump(self.model, model_path)
            logging.info("Created and saved default model")

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='ids_monitor.log'
        )
        # Add console handler to see logs in terminal
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger('').addHandler(console_handler)
        
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            timestamp = datetime.now()
            packet_info = self.extract_packet_features(packet)
            self.packet_queue.put((timestamp, packet_info))
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def extract_packet_features(self, packet):
        """Extract relevant features from the packet"""
        features = {
            'protocol': 0,
            'packet_size': len(packet),
            'flags': 0,
            'header_length': 0,
        }
        
        if 'IP' in packet:
            features['protocol'] = packet['IP'].proto
            
        if 'TCP' in packet:
            features['flags'] = packet['TCP'].flags
            features['header_length'] = packet['TCP'].dataofs
            
        return features

    def analyze_traffic(self):
        """Analyze captured traffic in real-time"""
        while not self.stop_flag.is_set():
            try:
                if not self.packet_queue.empty():
                    timestamp, packet_info = self.packet_queue.get()
                    
                    # Prepare features for model prediction
                    features = np.array([[
                        packet_info['protocol'],
                        packet_info['packet_size'],
                        packet_info['flags'],
                        packet_info['header_length']
                    ]])
                    
                    # Make prediction
                    prediction = self.model.predict(features)[0]
                    
                    if prediction == 1:
                        logging.warning(f"Potential intrusion detected at {timestamp}")
                        self.stats['intrusions'] += 1
                    
                    self.stats['packets_analyzed'] += 1
                    
            except Exception as e:
                logging.error(f"Error in analysis: {str(e)}")
            
            time.sleep(0.001)  # Small delay to prevent CPU overload

    def start_monitoring(self):
        """Start the monitoring process"""
        logging.info("Starting real-time monitoring...")
        
        try:
            # Test if we can capture packets
            test_capture = sniff(count=1, timeout=2)
            if not test_capture:
                logging.warning("No packets captured in test. Please ensure Npcap is installed and you have administrative privileges.")
        except Exception as e:
            logging.error(f"Error during packet capture test: {str(e)}")
            logging.error("Please ensure Npcap is installed and you have administrative privileges.")
            return None, None

        # Start packet capture thread
        capture_thread = threading.Thread(target=lambda: sniff(
            prn=self.packet_callback,
            store=0,
            stop_filter=lambda _: self.stop_flag.is_set()
        ))
        
        # Start analysis thread
        analysis_thread = threading.Thread(target=self.analyze_traffic)
        
        capture_thread.start()
        analysis_thread.start()
        
        return capture_thread, analysis_thread

    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.stop_flag.set()
        logging.info("Stopping monitoring...")
        logging.info(f"Statistics: {dict(self.stats)}")

if __name__ == "__main__":
    monitor = RealTimeMonitor()
    try:
        capture_thread, analysis_thread = monitor.start_monitoring()
        
        # Keep the main thread running
        while True:
            time.sleep(1)
            print(f"Packets analyzed: {monitor.stats['packets_analyzed']}, "
                  f"Intrusions detected: {monitor.stats['intrusions']}")
            
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop_monitoring()
        capture_thread.join()
        analysis_thread.join() 