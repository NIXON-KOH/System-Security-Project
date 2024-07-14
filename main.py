from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
import os
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import json

app = Flask(__name__)

# Replace with your VirusTotal API key
API_KEY = 'bca210d1aada642fef0d66febdeebed2db093e2e67903903708c45ca92f9d4dc'

UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Initialize VirusTotal API client
vt = VirusTotalPublicApi(API_KEY)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Calculate MD5 hash of the uploaded file
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
        file_md5 = md5_hash.hexdigest()
        file_md5 = "0f06a4736bff917f2390740a71db11d6"
        # Retrieve basic file report from VirusTotal using file_md5
        response = vt.get_file_report(file_md5)

        # Check for errors in the response
        if 'results' not in response or response['results']['response_code'] == 0:
            # If the file is not found on VirusTotal, upload it
            upload_response = vt.scan_file(file_path)
            if 'results' in upload_response:
                resource = upload_response['results']['resource']
            else:
                message = "Error in upload response"
                return render_template('result.html', message=message, report_url=None)

            # Notify the user to wait for the report
            message = "File is being scanned. Please refresh the page after a while to see the results."
            report_url = url_for('view_report', resource=resource)
            return render_template('result.html', message=message, report_url=report_url)

        # Check for malicious detection
        if 'results' in response and response['results'].get('positives', 0) > 0:
            message = "There is something wrong with the file. It may be malicious."
            report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
            return render_template('result.html', message=message, report_url=report_url)

        # If no malicious detection, upload is successful
        message = "File successfully uploaded."
        report_url = url_for('view_report', report=json.dumps(response, sort_keys=False, indent=4))
        return render_template('result.html', message=message, report_url=report_url)
    else:
        return 'Invalid file type'

@app.route('/report')
def view_report():
    resource = request.args.get('resource')
    if resource:
        response = vt.get_file_report(resource)
        if 'results' in response and response['results']['response_code'] != -2:
            report = json.dumps(response, sort_keys=False, indent=4)
            return render_template('report.html', report=report)
        else:
            message = "If view report not working, wait awhile and refresh"
            return render_template('result.html', message=message, report_url=url_for('view_report', resource=resource))
    else:
        report = request.args.get('report')
        return render_template('report.html', report=report)

if __name__ == '__main__':
    app.run(debug=True)
