"""
Network Intrusion Detection System Application

This module serves as the main entry point for the Flask web application.
It handles routing, model loading, and prediction logic for network intrusion detection.
"""

import numpy as np
from flask import Flask, request, jsonify, render_template
import joblib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
model = joblib.load('models/model.pkl')

EMAIL_ADDRESS = ""#your email address
EMAIL_PASSWORD = ""# USE APP PASSWORD

def send_email(subject, message, recipients):
    """
    Sends an email with an intrusion alert.

    Args:
        subject (str): The subject line of the email.
        message (dict): A dictionary containing the feature names and their values related to the intrusion.
        recipients (list[str]): A list of email addresses to receive the alert.
    
    Returns:
        None
    """
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

@app.route('/')
def home():
    """
    Renders the home page of the application.

    Returns:
        str: The rendered HTML content of 'home.html'.
    """
    return render_template('home.html')

@app.route('/ids') 
def ids():
    """
    Renders the intrusion detection system interface.

    Returns:
        str: The rendered HTML content of 'index.html'.
    """
    return render_template('index.html')

@app.route('/predict',methods=['POST'])
def predict():
    """
    Handles form submission for intrusion prediction.

    Reads feature values from the form, preprocesses them (one-hot encoding),
    uses the loaded model to predict the class of the network traffic, 
    sends an email alert if an intrusion is detected, and renders the result.

    Returns:
        str: The rendered HTML content of 'index.html' with the prediction output.
    """

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
    """
    Handles JSON requests for intrusion prediction via API.

    Reads JSON data, predicts the class using the loaded model,
    sends an email alert if an intrusion is detected, and returns the prediction.

    Returns:
        Response: A JSON response containing the prediction result (e.g., 'Normal', 'DOS').
    """

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

if __name__ == '__main__':
    app.debug = True
    app.run()
