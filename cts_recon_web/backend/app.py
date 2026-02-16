from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import sys
import importlib
import json
import threading
from datetime import datetime, timezone
from collections import defaultdict
import subprocess

# Add current directory to path so modules can be imported
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Define paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
MODULES_DIR_DEEP = os.path.join(BASE_DIR, 'modules')
MODULES_DIR_LITE = os.path.join(BASE_DIR, 'litemodules')

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# In-memory storage for scan status (for simplicity in this version)
# In production, use a database or Redis
scan_status = {}

def save_scan_file(domain, scan_type, scan_data):
    """Save scan data to a JSON file."""
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_{scan_type}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    scan_data["target"] = domain
    scan_data["scan_type"] = scan_type
    scan_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    scan_data["status"] = "completed"

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4)
        print(f"Scan saved to {filepath}")
        return filepath
    except Exception as e:
        print(f"Error saving scan file: {e}")
        return None

def run_module(module_name, domain, scan_data):
    """Run a single module."""
    try:
        module = importlib.import_module(module_name)
        importlib.reload(module)
        if hasattr(module, "process"):
            print(f"Running {module_name}...")
            result = module.process(domain)
            # Store result using the module's basename (e.g. 'subdomain' from 'litemodules.subdomain')
            scan_data[module_name.split('.')[-1]] = result
        else:
            print(f"Module {module_name} has no process function.")
    except Exception as e:
        print(f"Error running module {module_name}: {e}")
        scan_data[module_name.split('.')[-1]] = {"error": str(e)}

def run_scan_async(domain, scan_type, scan_id):
    """Execute the scan in a background thread."""
    print(f"Starting {scan_type} scan for {domain} (ID: {scan_id})")
    
    scan_data = {}
    modules_dir = MODULES_DIR_LITE if scan_type == 'lite' else MODULES_DIR_DEEP
    module_prefix = 'litemodules' if scan_type == 'lite' else 'modules'

    # 1. Update status to running
    scan_status[scan_id] = {"status": "running", "domain": domain, "type": scan_type, "start_time": datetime.now().isoformat()}

    # 2. Add modules to path if not already
    if modules_dir not in sys.path:
        sys.path.append(modules_dir)
        
    # 3. Iterate and run modules
    if os.path.exists(modules_dir):
        for filename in sorted(os.listdir(modules_dir)):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = f"{module_prefix}.{filename[:-3]}"
                run_module(module_name, domain, scan_data)
    
    # 4. Save results
    filepath = save_scan_file(domain, scan_type, scan_data)
    
    # 5. Update status to completed
    scan_status[scan_id]["status"] = "completed"
    scan_status[scan_id]["end_time"] = datetime.now().isoformat()
    if filepath:
         scan_status[scan_id]["result_file"] = os.path.basename(filepath)

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    domain = data.get('domain')
    scan_type = data.get('scan_type', 'deep') # Default to deep

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_id = f"{domain}_{scan_type}_{int(datetime.now().timestamp())}"
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan_async, args=(domain, scan_type, scan_id))
    thread.start()

    return jsonify({"message": "Scan started", "scan_id": scan_id})

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    status = scan_status.get(scan_id)
    if not status:
        return jsonify({"error": "Scan ID not found"}), 404
    return jsonify(status)

@app.route('/api/results', methods=['GET'])
def list_results():
    files = []
    if os.path.exists(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith(".json"):
                 files.append(f)
    # Sort by modification time (newest first)
    files.sort(key=lambda x: os.path.getmtime(os.path.join(OUTPUT_DIR, x)), reverse=True)
    return jsonify(files)

@app.route('/api/results/<filename>', methods=['GET'])
def get_result_detail(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": f"Error reading file: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
