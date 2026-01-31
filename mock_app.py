from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/ids')
def ids():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    return render_template('index.html', output='Normal')

@app.route('/results', methods=['POST'])
def results():
    return jsonify('Normal')

if __name__ == '__main__':
    app.run(port=5000, debug=True)
