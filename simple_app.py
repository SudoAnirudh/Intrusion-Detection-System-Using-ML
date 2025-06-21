from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from simple_ids_monitor import SimpleIDSMonitor
import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'simple_ids_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global monitor instance
monitor = None
stats_thread = None

def background_stats_update():
    """Send stats updates to clients"""
    while True:
        try:
            if monitor and not monitor.stop_flag.is_set():
                dashboard_data = monitor.get_dashboard_data()
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
    try:
        if monitor:
            return jsonify(monitor.get_dashboard_data())
        return jsonify({'error': 'Monitor not running'})
    except Exception as e:
        return jsonify({'error': f'Error getting stats: {str(e)}'})

@socketio.on('connect')
def handle_connect():
    print('Client connected to simple IDS dashboard')

@socketio.on('start_monitoring')
def handle_start_monitoring():
    global monitor, stats_thread
    try:
        if monitor is None:
            monitor = SimpleIDSMonitor()
            capture_thread, analysis_thread = monitor.start_monitoring()
            
            if capture_thread and analysis_thread:
                if stats_thread is None:
                    stats_thread = threading.Thread(target=background_stats_update)
                    stats_thread.daemon = True
                    stats_thread.start()
                
                emit('monitoring_status', {'status': 'started'})
            else:
                emit('monitoring_status', {'status': 'error', 'message': 'Failed to start monitoring'})
    except Exception as e:
        emit('monitoring_status', {'status': 'error', 'message': str(e)})

@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    global monitor
    try:
        if monitor:
            monitor.stop_monitoring()
            monitor = None
            emit('monitoring_status', {'status': 'stopped'})
    except Exception as e:
        emit('monitoring_status', {'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 