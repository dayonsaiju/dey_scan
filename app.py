from flask import Flask, request, render_template, redirect, url_for, send_file
import os
import uuid
from androguard.misc import AnalyzeAPK
from reportlab.pdfgen import canvas

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/', methods=['GET', 'POST'])
def index():
    """Display the homepage with the upload form."""
    if request.method == 'POST':
        apk_file = request.files.get('apk_file')
        if apk_file and apk_file.filename.endswith('.apk'):
            # Save the file with a unique name
            file_path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4()}.apk")
            apk_file.save(file_path)
            # Redirect to scanning page
            return redirect(url_for('scan', file_name=os.path.basename(file_path)))
    return render_template('index.html')

@app.route('/scan/<file_name>')
def scan(file_name):
    """Analyze the uploaded APK and show results."""
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    safe = True
    issues = []
    try:
        # Use Androguard to parse the APK.
        a, d, dx = AnalyzeAPK(file_path)
        permissions = a.get_permissions()

        # Example check: if the APK requests a sensitive permission.
        if "android.permission.READ_SMS" in permissions:
            safe = False
            issues.append("App requests a sensitive permission: READ_SMS")
        
        # Further checks can be added here.
    except Exception as e:
        safe = False
        issues.append("Error analyzing APK: " + str(e))
    
    # Prepare and show the scan report.
    report = {
        'safe': safe,
        'issues': issues,
        'file_name': file_name
    }
    return render_template('result.html', report=report)

@app.route('/download_report/<file_name>')
def download_report(file_name):
    """Generate and serve a PDF report of the scan."""
    pdf_path = os.path.join(UPLOAD_FOLDER, f"{file_name}.pdf")
    c = canvas.Canvas(pdf_path)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(100, 800, "Day Scan Report")
    c.setFont("Helvetica", 12)
    c.drawString(100, 770, f"APK File: {file_name}")
    c.drawString(100, 740, "Scan Details:")
    c.drawString(120, 720, "- Example Detail: APK structure OK")
    c.save()
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
