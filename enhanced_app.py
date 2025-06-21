from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from enhanced_ids_monitor import EnhancedIDSMonitor
import threading
import time
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'enhanced_ids_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitor instance
monitor = None
stats_thread = None

def background_stats_update():
    """Send comprehensive stats updates to clients"""
    while True:
        if monitor and not monitor.stop_flag.is_set():
            try:
                dashboard_data = monitor.get_dashboard_data()
                socketio.emit('dashboard_update', dashboard_data)
            except Exception as e:
                print(f"Error updating dashboard: {str(e)}")
        time.sleep(2)  # Update every 2 seconds

@app.route('/')
def index():
    return render_template('enhanced_dashboard.html')

@app.route('/api/stats')
def get_stats():
    if monitor:
        return jsonify(monitor.get_dashboard_data())
    return jsonify({'error': 'Monitor not running'})

@socketio.on('connect')
def handle_connect():
    print('Client connected to enhanced IDS dashboard')

@socketio.on('start_monitoring')
def handle_start_monitoring():
    global monitor, stats_thread
    if monitor is None:
        monitor = EnhancedIDSMonitor()
        capture_thread, analysis_thread = monitor.start_monitoring()
        
        if stats_thread is None:
            stats_thread = threading.Thread(target=background_stats_update)
            stats_thread.daemon = True
            stats_thread.start()
        
        emit('monitoring_status', {'status': 'started'})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    global monitor
    if monitor:
        monitor.stop_monitoring()
        monitor = None
        emit('monitoring_status', {'status': 'stopped'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 