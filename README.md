# Network Intrusion Detection System

This project is a Network Intrusion Detection System (NIDS) that uses machine learning algorithms to detect various types of network intrusions. The system is built using Flask for the web interface and scikit-learn for the machine learning models.

## Project Structure

- `app.py`: The main Flask application file.
- `models/`: Directory containing the trained machine learning model.
- `NSL_Dataset/`: Directory containing the training and testing datasets.
- `static/`: Directory containing static files like CSS.
- `templates/`: Directory containing HTML templates.
- `corrm.csv`: Correlation matrix CSV file.
- `num_summary.csv`: Numerical summary CSV file.
- `pandas_profiling.html`: HTML report generated by pandas profiling.
- `requirements.txt`: List of Python dependencies.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/SudoAnirudh/Intrusion-Detection-System-Using-ML.git
    cd nids
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

4. Download the NSL-KDD dataset and place `Train.txt` and `Test.txt` in the  directory.

## Usage

1. Run the Flask application:
    ```sh
    python app.py
    ```

2. Open your web browser and go to `http://127.0.0.1:5000/`.

3. Use the web interface to input network features and get predictions for potential intrusions.

## Features

- **Machine Learning Models**: Uses various machine learning algorithms like Decision Trees, Random Forest, SVM, etc., to detect intrusions.
- **Web Interface**: User-friendly web interface to input network features and view predictions.
- **Email Alerts**: Sends email alerts when an intrusion is detected.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.