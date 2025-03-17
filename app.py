import numpy as np
from flask import Flask, request, jsonify, render_template
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_socketio import SocketIO, emit
from real_time_monitor import RealTimeMonitor
import threading
import time
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

model = joblib.load('models/model.pkl')

EMAIL_ADDRESS = ""#your email address
EMAIL_PASSWORD = ""# USE APP PASSWORD

# Global monitor instance
monitor = None
stats_thread = None

def send_email(subject, message, recipients):
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = ", ".join(recipients)
    
    attack_names = {
        '0': 'Normal',
        '1': 'DOS',
        '2': 'PROBE',
        '3': 'R2L',
        '4': 'U2R'
    }

    html_message = f"""
    <table border="1" style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
        <thead style="background-color: #f2f2f2;">
            <tr>
                <th style="padding: 8px; text-align: left;">Feature</th>
                <th style="padding: 8px; text-align: left;">Value</th>
            </tr>
        </thead>
        <tbody>
            {''.join(f'<tr><td style="padding: 8px; text-align: left;">{key}</td><td style="padding: 8px; text-align: left;">{attack_names.get(value, value)}</td></tr>' for key, value in message.items())}
        </tbody>
    </table>
    """
    msg.attach(MIMEText(html_message, 'html'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:  # Or your SMTP server
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

def background_stats_update():
    """Send stats updates to clients periodically"""
    while True:
        if monitor and not monitor.stop_flag.is_set():
            stats_data = {
                'packets_analyzed': monitor.stats['packets_analyzed'],
                'intrusions': monitor.stats['intrusions'],
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            socketio.emit('stats_update', stats_data)
        time.sleep(1)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/ids') 
def ids():
    return render_template('index.html')

@app.route('/predict',methods=['POST'])
def predict():

    int_features = [float(x) for x in request.form.values()]

    if int_features[0]==0:
        f_features=[0,0,0]+int_features[1:]
    elif int_features[0]==1:
        f_features=[1,0,0]+int_features[1:]
    elif int_features[0]==2:
        f_features=[0,1,0]+int_features[1:]
    else:
        f_features=[0,0,1]+int_features[1:]

    if f_features[6]==0:
        fn_features=f_features[:6]+[0,0]+f_features[7:]
    elif f_features[6]==1:
        fn_features=f_features[:6]+[1,0]+f_features[7:]
    else:
        fn_features=f_features[:6]+[0,1]+f_features[7:]

    final_features = [np.array(fn_features)]
    predict = model.predict(final_features)

    if predict==0:
        output='Normal'
    elif predict==1:
        output='DOS'
    elif predict==2:
        output='PROBE'
    elif predict==3:
        output='R2L'
    else:
        output='U2R'

    if output != "Normal":
        # Send email alert
        send_email(
            subject="Intrusion Alert!",
            message={key: value for key, value in request.form.items()},
            recipients=[""] #RECIPIENT MAIL
        )

    return render_template('index.html', output=output)

@app.route('/results',methods=['POST'])
def results():

    data = request.get_json(force=True)
    predict = model.predict([np.array(list(data.values()))])

    if predict==0:
        output='Normal'
    elif predict==1:
        output='DOS'
    elif predict==2:
        output='PROBE'
    elif predict==3:
        output='R2L'
    else:
        output='U2R'

    if output != "Normal":
       
        send_email(
            subject="Intrusion Alert!",
            message={key: value for key, value in data.items()},
            recipients=["recipient1@example.com", "recipient2@example.com"] 
        )

    return jsonify(output)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('start_monitoring')
def handle_start_monitoring():
    global monitor, stats_thread
    if monitor is None:
        monitor = RealTimeMonitor()
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
    socketio.run(app, debug=True)
