from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import threading
import time
import random
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'simulation_ids_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Simulation data
simulation_data = {
    'total_packets': 0,
    'intrusions_detected': 0,
    'anomalies_detected': 0,
    'port_scan_attempts': 0,
    'ddos_attempts': 0,
    'suspicious_ips': [],
    'active_flows': 0,
    'recent_alerts': [],
    'top_flows': [],
    'suspicious_ips_list': []
}

stop_simulation = threading.Event()

def generate_simulation_data():
    """Generate realistic simulation data"""
    while not stop_simulation.is_set():
        try:
            # Simulate packet capture
            simulation_data['total_packets'] += random.randint(10, 50)
            
            # Simulate occasional intrusions
            if random.random() < 0.1:  # 10% chance
                simulation_data['intrusions_detected'] += 1
                simulation_data['anomalies_detected'] += 1
                
                # Create fake alert
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': f"192.168.1.{random.randint(1, 254)}",
                    'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                    'anomalies': random.choice([
                        ['port_scan'],
                        ['ddos_attempt'],
                        ['suspicious_port_access'],
                        ['unusual_packet_size']
                    ]),
                    'packet_size': random.randint(64, 1500)
                }
                
                simulation_data['recent_alerts'].append(alert)
                if len(simulation_data['recent_alerts']) > 10:
                    simulation_data['recent_alerts'].pop(0)
            
            # Simulate port scans
            if random.random() < 0.05:  # 5% chance
                simulation_data['port_scan_attempts'] += 1
            
            # Simulate DDoS attempts
            if random.random() < 0.02:  # 2% chance
                simulation_data['ddos_attempts'] += 1
            
            # Simulate suspicious IPs
            if random.random() < 0.03:  # 3% chance
                suspicious_ip = f"192.168.1.{random.randint(1, 254)}"
                if suspicious_ip not in simulation_data['suspicious_ips_list']:
                    simulation_data['suspicious_ips_list'].append(suspicious_ip)
                    if len(simulation_data['suspicious_ips_list']) > 10:
                        simulation_data['suspicious_ips_list'].pop(0)
            
            # Simulate network flows
            simulation_data['active_flows'] = random.randint(5, 20)
            
            # Generate fake flows
            flows = []
            for i in range(min(5, simulation_data['active_flows'])):
                flows.append([
                    f"192.168.1.{random.randint(1, 254)}_10.0.0.{random.randint(1, 254)}",
                    {
                        'packet_count': random.randint(10, 1000),
                        'ports': [random.randint(80, 443) for _ in range(random.randint(1, 5))]
                    }
                ])
            simulation_data['top_flows'] = flows
            
            time.sleep(2)  # Update every 2 seconds
            
        except Exception as e:
            print(f"Error in simulation: {str(e)}")
            time.sleep(5)

def get_simulation_dashboard_data():
    """Get simulation dashboard data"""
    return {
        'statistics': {
            'total_packets': simulation_data['total_packets'],
            'intrusions_detected': simulation_data['intrusions_detected'],
            'anomalies_detected': simulation_data['anomalies_detected'],
            'port_scan_attempts': simulation_data['port_scan_attempts'],
            'ddos_attempts': simulation_data['ddos_attempts'],
            'suspicious_ips_count': len(simulation_data['suspicious_ips_list']),
            'active_flows': simulation_data['active_flows']
        },
        'recent_alerts': simulation_data['recent_alerts'],
        'suspicious_ips': simulation_data['suspicious_ips_list'],
        'top_flows': simulation_data['top_flows'],
        'timestamp': datetime.now().isoformat()
    }

def background_stats_update():
    """Send simulation stats updates to clients"""
    while not stop_simulation.is_set():
        try:
            dashboard_data = get_simulation_dashboard_data()
            socketio.emit('dashboard_update', dashboard_data)
            time.sleep(2)
        except Exception as e:
            print(f"Error updating dashboard: {str(e)}")
            time.sleep(5)

@app.route('/')
def index():
    return render_template('simple_dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(get_simulation_dashboard_data())

@socketio.on('connect')
def handle_connect():
    print('Client connected to simulation IDS dashboard')

@socketio.on('start_monitoring')
def handle_start_monitoring():
    global stop_simulation
    try:
        stop_simulation.clear()
        
        # Start simulation thread
        simulation_thread = threading.Thread(target=generate_simulation_data)
        simulation_thread.daemon = True
        simulation_thread.start()
        
        # Start stats update thread
        stats_thread = threading.Thread(target=background_stats_update)
        stats_thread.daemon = True
        stats_thread.start()
        
        emit('monitoring_status', {'status': 'started'})
        print("Simulation monitoring started")
        
    except Exception as e:
        emit('monitoring_status', {'status': 'error', 'message': str(e)})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    global stop_simulation
    try:
        stop_simulation.set()
        emit('monitoring_status', {'status': 'stopped'})
        print("Simulation monitoring stopped")
    except Exception as e:
        emit('monitoring_status', {'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    print("Starting IDS Simulation Mode")
    print("This mode generates fake network data for testing the dashboard")
    print("Access the dashboard at: http://localhost:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 