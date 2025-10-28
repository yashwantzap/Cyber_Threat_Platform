import subprocess
from flask import Flask, request, jsonify, send_from_directory
import os
import sys

# Change the working directory to the project's root for subprocess calls
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Ensure Flask is installed before running
try:
    from flask_cors import CORS
except ImportError:
    print("Flask-CORS is not installed. Please install it with: pip install Flask-CORS")
    sys.exit(1)

app = Flask(__name__)
CORS(app)  # This allows your HTML file to make requests to the server

def run_script(script_name, args=None):
    """
    Runs a Python script using subprocess and captures its output.
    Returns a tuple (success, stdout_output, stderr_output).
    """
    try:
        command = [sys.executable, script_name]
        if args:
            command.extend(args)
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr
    except FileNotFoundError:
        return False, "", f"Error: Script '{script_name}' not found."

@app.route('/')
def serve_index():
    """Serves the index.html file from the same directory."""
    dir_path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(dir_path, 'index.html')
    
    # Check if the file exists and print a diagnostic message
    if not os.path.exists(file_path):
        print(f"ERROR: index.html not found at: {file_path}")
        return "Internal Server Error: index.html not found.", 500
    
    return send_from_directory(dir_path, 'index.html')

@app.route('/api/collect_data', methods=['POST'])
def collect_data():
    """Endpoint to run data_collector.py."""
    print("API: Received request to collect data...")
    success, stdout, stderr = run_script("data_collector.py")
    if success:
        return jsonify({"status": "success", "message": stdout})
    else:
        return jsonify({"status": "error", "message": stderr}), 500

@app.route('/api/train_model', methods=['POST'])
def train_model():
    """Endpoint to run threat_predictor.py."""
    print("API: Received request to train model...")
    success, stdout, stderr = run_script("threat_predictor.py")
    if success:
        return jsonify({"status": "success", "message": stdout})
    else:
        return jsonify({"status": "error", "message": stderr}), 500

@app.route('/api/analyze_vulnerability', methods=['POST'])
def analyze_vulnerability():
    """
    Endpoint to run threat_mitigation.py with a specific CVE ID.
    Note: Your threat_mitigation.py script needs to be modified to accept
    command-line arguments instead of interactive input.
    """
    print("API: Received request to analyze a vulnerability...")
    try:
        data = request.json
        cve_id = data.get('cveID')
        if not cve_id:
            return jsonify({"status": "error", "message": "Missing cveID"}), 400

        # Run the mitigation script with the CVE ID as an argument
        success, stdout, stderr = run_script("threat_mitigation.py", args=["--cve_id", cve_id])
        
        if success:
            # The stdout will contain the analysis results. We need to parse it.
            # A better long-term solution would be to have the Python script
            # return JSON directly. For this example, we'll return the raw text.
            return jsonify({"status": "success", "message": "Analysis complete", "result": stdout})
        else:
            return jsonify({"status": "error", "message": stderr}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Use 0.0.0.0 to make the server accessible from outside the container
    app.run(host='0.0.0.0', port=5000)
