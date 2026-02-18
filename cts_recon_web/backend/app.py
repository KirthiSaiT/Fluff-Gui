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
import re
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add current directory to path so modules can be imported
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Define paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
MODULES_DIR_DEEP = os.path.join(BASE_DIR, 'modules')
MODULES_DIR_LITE = os.path.join(BASE_DIR, 'litemodules')

# Ensure output directory exists (still used for temp storage if needed, or fallback)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# MongoDB Connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/cts_recon")
try:
    client = MongoClient(MONGO_URI)
    # Default to 'cts_recon' if no db specified in URI
    db = client.get_database("cts_recon") 
    scans_collection = db.scans
    print(f"Connected to MongoDB: {db.name}")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    sys.exit(1)

class ThreadAwareStdout:
    def __init__(self, original_stdout):
        # Prevent recursive wrapping
        if isinstance(original_stdout, ThreadAwareStdout):
            self.original_stdout = original_stdout.original_stdout
        else:
            self.original_stdout = original_stdout

    def write(self, message):
        # Avoid writing if interpreter is shutting down
        if sys is None or not hasattr(sys, 'modules'):
            return

        # 1. Capture log for UI (Safe, pure python ops)
        try:
            current_thread = threading.current_thread()
            if hasattr(current_thread, 'scan_id'):
                scan_id = current_thread.scan_id
                
                # Strip ANSI escape codes
                clean_message = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', message)
                
                # Only log if there's actual content
                if clean_message.strip():
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    log_entry = f"[{timestamp}] {clean_message.strip()}"
                    
                    # Update MongoDB directly
                    scans_collection.update_one(
                        {"scan_id": scan_id},
                        {"$push": {"logs": log_entry}}
                    )
        except Exception:
            pass # Ignore logging errors to prevent crashing

        # 2. Write to original stdout
        try:
            self.original_stdout.write(message)
        except Exception:
            pass

    def flush(self):
        try:
            self.original_stdout.flush()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self.original_stdout, name)

# Replace stdout globally
if not isinstance(sys.stdout, ThreadAwareStdout):
    sys.stdout = ThreadAwareStdout(sys.stdout)

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

    # Set scan_id on current thread for logging
    threading.current_thread().scan_id = scan_id

    # 1. Update status to running (already created in start_scan)
    scans_collection.update_one(
        {"scan_id": scan_id},
        {"$set": {"status": "running", "start_time": datetime.now().isoformat()}}
    )

    # 2. Add modules to path if not already
    if modules_dir not in sys.path:
        sys.path.append(modules_dir)
        
    # 3. Iterate and run modules
    if os.path.exists(modules_dir):
        for filename in sorted(os.listdir(modules_dir)):
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = f"{module_prefix}.{filename[:-3]}"
                run_module(module_name, domain, scan_data)
    
    # 4. Update status to completed and save results
    scans_collection.update_one(
        {"scan_id": scan_id},
        {
            "$set": {
                "status": "completed",
                "end_time": datetime.now().isoformat(),
                "results": scan_data
            }
        }
    )
    print(f"Scan {scan_id} completed and saved to MongoDB.")

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    data = request.json
    domain = data.get('domain')
    scan_type = data.get('scan_type', 'deep') # Default to deep

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    scan_id = f"{domain}_{scan_type}_{int(datetime.now().timestamp())}"
    
    # Create initial document
    scans_collection.insert_one({
        "scan_id": scan_id,
        "domain": domain,
        "type": scan_type,
        "status": "initializing",
        "created_at": datetime.now().isoformat(),
        "logs": [],
        "results": {}
    })

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_async, args=(domain, scan_type, scan_id))
    thread.daemon = True # Ensure thread dies if server stops
    thread.start()

    return jsonify({"message": "Scan started", "scan_id": scan_id})

@app.route('/api/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    scan = scans_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        return jsonify({"error": "Scan ID not found"}), 404
    return jsonify(scan)

@app.route('/api/results', methods=['GET'])
def list_results():
    # Return list of completed scans, sorted by latest
    cursor = scans_collection.find({}, {"_id": 0, "scan_id": 1, "domain": 1, "type": 1, "status": 1, "created_at": 1, "end_time": 1}).sort("created_at", -1)
    results = list(cursor)
    return jsonify(results)

@app.route('/api/results/<scan_id>', methods=['GET'])
def get_result_detail(scan_id):
    scan = scans_collection.find_one({"scan_id": scan_id}, {"_id": 0, "results": 1, "domain": 1, "type": 1, "start_time": 1, "end_time": 1})
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Return structure aimed at matching previous file output, or just the whole object
    return jsonify(scan)

@app.route('/api/stats', methods=['GET'])
def get_stats():
    total_scans = scans_collection.count_documents({})
    completed_scans = scans_collection.count_documents({"status": "completed"})
    running_scans = scans_collection.count_documents({"status": "running"})
    return jsonify({
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
