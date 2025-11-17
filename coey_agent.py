
import os
from flask import Flask, request, render_template_string, redirect, url_for, flash
import anthropic

import zipfile
import io
from flask import send_file
import json

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

# Endpoint to get dashboard structure (menus/tabs)
@app.route('/dashboard-structure', methods=['GET'])
def get_dashboard_structure():
    try:
        with open('dashboard_structure.json', 'r') as f:
            structure = json.load(f)
        return structure
    except Exception as e:
        return {"error": str(e)}, 500

# Endpoint to update dashboard structure (menus/tabs)
@app.route('/dashboard-structure', methods=['POST'])
def update_dashboard_structure():
    data = request.get_json()
    if not data:
        return {"error": "No data provided."}, 400
    try:
        with open('dashboard_structure.json', 'w') as f:
            json.dump(data, f, indent=2)
        return {"success": True}
    except Exception as e:
        return {"error": str(e)}, 500

CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY', 'your-claude-api-key-here')
client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Coey Bot Backoffice</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        textarea { width: 100%; height: 100px; }
        .response { margin-top: 20px; padding: 10px; background: #f0f0f0; border-radius: 5px; }
        .upload-section { margin-top: 30px; padding: 20px; background: #e9e9e9; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Coey Bot Backoffice</h1>
    <form method="post" action="/ask">
        <label for="prompt">Enter your order for Claude:</label><br>
        <textarea id="prompt" name="prompt"></textarea><br><br>
        <button type="submit">Send to Claude</button>
    </form>
    {% if response %}
    <div class="response">
        <strong>Claude's Response:</strong><br>
        {{ response }}
    </div>
    {% endif %}

    <div class="upload-section">
        <h2>Upload Files or Zipped Folders</h2>
        <form method="post" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" multiple required>
            <button type="submit">Upload</button>
        </form>
        {% if upload_message %}
        <div class="response">{{ upload_message }}</div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

# File upload endpoint
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template_string(HTML_TEMPLATE, upload_message="No file part in the request.")
    files = request.files.getlist('file')
    saved_files = []
    for file in files:
        if file.filename == '':
            continue
        save_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(save_path)
        # If it's a zip file, extract it
        if file.filename.lower().endswith('.zip'):
            with zipfile.ZipFile(save_path, 'r') as zip_ref:
                zip_ref.extractall(UPLOAD_FOLDER)
            os.remove(save_path)
            saved_files.append(f"Extracted {file.filename}")
        else:
            saved_files.append(f"Saved {file.filename}")
    msg = "<br>".join(saved_files) if saved_files else "No files uploaded."
    return render_template_string(HTML_TEMPLATE, upload_message=msg)

@app.route('/ask', methods=['POST'])
def ask_claude():
    prompt = request.form.get('prompt', '')
    if not prompt:
        return render_template_string(HTML_TEMPLATE, response="Please enter a prompt.")
    try:
        response = client.beta.messages.create(
            model="claude-sonnet-4-5",  # Update model as needed
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt}
                    ]
                }
            ],
            betas=["files-api-2025-04-14"],
        )
        ai_response = response.content[0].text if hasattr(response, 'content') and response.content else 'No response from Claude.'
    except Exception as e:
        ai_response = f"Error: {e}"
    return render_template_string(HTML_TEMPLATE, response=ai_response)

# Endpoint to download all project files as a zip
@app.route('/download-all', methods=['GET'])
def download_all():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for foldername, subfolders, filenames in os.walk('.'):
            # Skip virtual environments and hidden folders
            if any(skip in foldername for skip in ['.git', '__pycache__', 'venv', '.venv', 'node_modules', '.idea', '.vscode']):
                continue
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                # Skip hidden files and pyc files
                if filename.startswith('.') or filename.endswith('.pyc'):
                    continue
                zf.write(filepath, os.path.relpath(filepath, '.'))
    memory_file.seek(0)
    return send_file(memory_file, download_name='project.zip', as_attachment=True)

# Endpoint to generate a guide or code using Claude
@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    prompt = data.get('prompt', '')
    if not prompt:
        return {"error": "No prompt provided."}, 400
    try:
        response = client.beta.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1024,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt}
                    ]
                }
            ],
            betas=["files-api-2025-04-14"],
        )
        ai_response = response.content[0].text if hasattr(response, 'content') and response.content else 'No response from Claude.'
        return {"result": ai_response}
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
