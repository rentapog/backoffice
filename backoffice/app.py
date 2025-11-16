from flask import Flask, render_template, request, jsonify
import requests
import os

app = Flask(__name__)

# Load Claude API key from environment variable or config
CLAUDE_API_KEY = os.getenv('CLAUDE_API_KEY', 'your-claude-api-key-here')
CLAUDE_API_URL = 'https://api.anthropic.com/v1/messages'  # Update if needed

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/claude', methods=['POST'])
def claude():
    user_input = request.json.get('message')
    headers = {
        'x-api-key': CLAUDE_API_KEY,
        'content-type': 'application/json'
    }
    data = {
        'model': 'claude-3-opus-20240229',
        'messages': [
            {'role': 'user', 'content': user_input}
        ],
        'max_tokens': 1024
    }
    response = requests.post(CLAUDE_API_URL, headers=headers, json=data)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({'error': response.text}), response.status_code

if __name__ == '__main__':
    app.run(debug=True)
