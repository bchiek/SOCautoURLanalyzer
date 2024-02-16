from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests
import time
import os 

# Load environment variables
load_dotenv()

# Flask
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(debug=True)

# VirusTotal API
def call_VT_api(url):
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    params = {'apikey': api_key, 'resource': url}
    headers = {"Accept": "application/json"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Failed to fetch data from VirusTotal"}

# URLSCAN API
def call_URLSCAN_api(url):
    apikey = os.getenv('URLSCAN_API_KEY')
    headers = {'API-Key': apikey, 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    submit_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)

    if submit_response.status_code == 200:
        scan_uuid = submit_response.json().get('uuid')
        # Wait a bit before starting to poll for results to give the scan time to start
        time.sleep(10)
        
        # Poll for results
        for _ in range(5):  # Adjust the range as necessary
            status_response = requests.get(f'https://urlscan.io/api/v1/result/{scan_uuid}/', headers=headers)
            if status_response.status_code == 200:
                # Assuming the scan is complete if we can get the result
                return {
                    "result_uuid": scan_uuid,
                    "result_message": "Scan complete",
                    "result_screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png"
                }
            time.sleep(10)  # Adjust the sleep time as necessary
    elif submit_response.status_code == 429:
        return {"error": "Rate limited by URLscan.io. Please try again later."}
    else:
        # General error handling
        error_message = submit_response.json().get('message', 'Failed to submit URL to URLscan.io')
        return {"error": f"{submit_response.status_code}: {error_message}"}

# Qualys SSL API
# Based on API v3 as v4 requires registration: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
QUALYS_API_URL = 'https://api.ssllabs.com/api/v3/'

def call_QUALYS_api(path, payload={}):
    # Helper method to request data from Qualys SSL Labs API.
    qualys_url = QUALYS_API_URL + path
    try:
        response = requests.get(qualys_url, params=payload)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 10))
            time.sleep(retry_after)
            return call_QUALYS_api(path, payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        return None

def analyze_ssl(url):
    # Initiates SSL analysis and polls for results.
    payload = {
        'host': urlparse(url).netloc,
        'publish': 'off',
        'startNew': 'on',
        'all': 'done',
        'ignoreMismatch': 'on'
    }
    
    # Start new scan
    data = call_QUALYS_api('analyze', payload)
    if not data:
        return {"error": "Failed to initiate SSL analysis."}
    
    # Poll for completion
    payload['startNew'] = 'off'
    payload['fromCache'] = 'on'
    while data and data.get('status') not in ['READY', 'ERROR']:
        time.sleep(15)  # Adjust as needed
        data = call_QUALYS_api('analyze', payload)
    
    return data

# Routes
@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Call API functions
    vt_results = call_VT_api(url)
    urlscan_results = call_URLSCAN_api(url)
    qualys_results = analyze_ssl(url)
    
    # Prepare the results
    results = {
        "virustotal": vt_results,
        "urlscan": urlscan_results,
        "qualys": qualys_results,
    }

    print (qualys_results)

    return render_template('results.html', results=results, url=url)

if __name__ == '__main__':
    app.run(debug=True)