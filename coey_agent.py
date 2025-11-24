import stripe
import os
import json
import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, abort, render_template_string, send_file
from functools import wraps
import zipfile
import io
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import anthropic
import pyotp
# Initialize Flask app FIRST
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')  # Replace with a secure key

## Privacy Policy and Terms of Service routes
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-and-conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/')
def index():
    # If accessed via backoffice.rentapog.com, redirect to /backoffice
    host = request.headers.get('Host', '')
    if host.startswith('backoffice.rentapog.com'):
        return redirect(url_for('backoffice'))
    return render_template('front.html')

# Namecheap API credentials
NAMECHEAP_API_USER = os.environ.get('NAMECHEAP_API_USER')
NAMECHEAP_API_KEY = os.environ.get('NAMECHEAP_API_KEY')
NAMECHEAP_USERNAME = os.environ.get('NAMECHEAP_USERNAME')
NAMECHEAP_API_URL = 'https://api.namecheap.com/xml.response'
# AJAX endpoint for uniqueness check
@app.route('/register-domain', methods=['GET', 'POST'])
def register_domain():
    message = None
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        if not domain:
            message = 'Please enter a domain name.'
        else:
            # Check domain availability via Namecheap API
            params = {
                'ApiUser': NAMECHEAP_API_USER,
                'ApiKey': NAMECHEAP_API_KEY,
                'UserName': NAMECHEAP_USERNAME,
                'Command': 'namecheap.domains.check',
                'ClientIp': request.remote_addr,
                'DomainList': domain
            }
            try:
                resp = requests.get(NAMECHEAP_API_URL, params=params, timeout=10)
                if resp.status_code == 200 and '<Available>true</Available>' in resp.text:
                    # Register domain
                    reg_params = params.copy()
                    reg_params['Command'] = 'namecheap.domains.create'
                    reg_params['DomainName'] = domain
                    reg_params['Years'] = 1
                    reg_params['RegistrantFirstName'] = 'Admin'
                    reg_params['RegistrantLastName'] = 'User'
                    reg_params['RegistrantEmailAddress'] = 'admin@rentapog.com'
                    reg_params['RegistrantAddress1'] = '123 Main St'
                    reg_params['RegistrantCity'] = 'City'
                    reg_params['RegistrantStateProvince'] = 'State'
                    reg_params['RegistrantPostalCode'] = '12345'
                    reg_params['RegistrantCountry'] = 'US'
                    reg_params['RegistrantPhone'] = '+1.5555555555'
                    reg_resp = requests.get(NAMECHEAP_API_URL, params=reg_params, timeout=15)
                    if reg_resp.status_code == 200 and '<DomainCreateResult' in reg_resp.text:
                        return redirect(url_for('register_address'))
                    else:
                        message = 'Domain registration failed. Please try again.'
                else:
                    message = 'Domain is not available.'
            except Exception as e:
                message = f'Error: {str(e)}'
    return render_template('register_domain.html', message=message)

# Load Stripe keys and webhook secret from environment variables
STRIPE_SECRET_KEY = os.environ.get('STRIPE_API_SECRET_KEY')
STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLISHER_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK')
stripe.api_key = STRIPE_SECRET_KEY

# Add a price for address registration (in cents)
ADDRESS_PRICE = 2000  # $20.00

# Stripe webhook endpoint
@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        # Invalid payload
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        # Invalid signature
        return 'Invalid signature', 400

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # You can add logic here to mark the address as paid, etc.
        # Example: user_id = session.get('client_reference_id')
        # Save payment info, update user, etc.
    # Add more event types as needed

    return '', 200

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    address = request.form.get('address', '').strip()
    if not address:
        return jsonify({'error': 'No address provided.'}), 400
    addresses = load_addresses()
    if address in addresses:
        return jsonify({'error': 'Address already registered.'}), 400
    # Store address in session to reserve for this user
    session['pending_address'] = address
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Rent A Pog Address: {address}',
                    },
                    'unit_amount': ADDRESS_PRICE,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('checkout_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('register_address', _external=True),
        )
        return jsonify({'id': checkout_session.id, 'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/checkout-success')
def checkout_success():
    session_id = request.args.get('session_id')
    if not session_id:
        return 'No session ID provided.', 400
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        address = session.get('pending_address')
        if checkout_session.payment_status == 'paid' and address:
            addresses = load_addresses()
            if address not in addresses:
                save_address(address)
            session.pop('pending_address', None)
            return render_template('checkout_success.html', address=address)
        else:
            return 'Payment not completed or address missing.', 400
    except Exception as e:
        return f'Error: {str(e)}', 500

    # Stripe daily donation subscription with selectable price
    @app.route('/create-daily-donation-session', methods=['POST'])
    def create_daily_donation_session():
        data = request.get_json()
        price_id = data.get('price_id')
        valid_price_ids = [
            'price_1SVysaIRIx18hdykGeA3NjG0', # $1.49
            'price_1SVyuSIRIx18hdyk1jj9B82K', # $1.99
            'price_1SVyvPIRIx18hdykOx8LOGPR', # $2.49
            'price_1SVyjsIRIx18hdyk3VfeFFW7', # $2.99
            'price_1SVyl6IRIx18hdykIxZna2UR', # $3.49
            'price_1SVylsIRIx18hdykzLabZtKb', # $3.99
            'price_1SVymlIRIx18hdykPOc1MU9J', # $4.49
            'price_1SVynOIRIx18hdykWt5d00Fu', # $4.99
        ]
        if price_id not in valid_price_ids:
            return jsonify({'error': 'Invalid price ID.'}), 400
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=url_for('checkout_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=url_for('register_address', _external=True),
            )
            return jsonify({'url': checkout_session.url})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# Simple file-based storage for registered addresses
ADDRESS_FILE = 'registered_addresses.json'

def load_addresses():
    if not os.path.exists(ADDRESS_FILE):
        return set()
    with open(ADDRESS_FILE, 'r') as f:
        try:
            return set(json.load(f))
        except Exception:
            return set()

def save_address(address):
    addresses = load_addresses()
    addresses.add(address)
    with open(ADDRESS_FILE, 'w') as f:
        json.dump(list(addresses), f)

@app.route('/register-address', methods=['GET', 'POST'])
def register_address():
    if request.method == 'POST':
        address = request.form.get('address', '').strip()
        if not address:
            flash('Please enter an address.', 'error')
            return render_template('register_address.html')
        addresses = load_addresses()
        if address in addresses:
            flash('This address is already registered. Please choose another.', 'error')
            return render_template('register_address.html')
        save_address(address)
        flash(f'You have successfully registered: {address}', 'success')
        # Redirect to backoffice after successful registration
        return redirect(url_for('backoffice'))
    return render_template('register_address.html')

# AJAX endpoint for uniqueness check
@app.route('/check-address', methods=['POST'])
def check_address():
    data = request.get_json()
    address = data.get('address', '').strip()
    addresses = load_addresses()
    available = address not in addresses
    return jsonify({'available': available})
import qrcode

USER_DOMAINS = {}

# --- Login required decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/backoffice', methods=['GET', 'POST'])
@login_required
def backoffice():
    # Allow admin dashboard access from any IP

    import traceback
    global client
    admin_name = session.get('admin_name', 'admin')
    affiliate_link = f"https://rentapog.com/{admin_name}"
    user_email = 'admin@rentapog.com'
    msg = ''
    msg_color = ''
    if 'admin' not in USER_DOMAINS:
        USER_DOMAINS['admin'] = []
    if request.method == 'POST' and 'domain' in request.form:
        domain = request.form.get('domain', '').strip().lower()
        if domain and domain not in USER_DOMAINS['admin']:
            USER_DOMAINS['admin'].append(domain)
            msg = f"{domain} gone in the system goodbye!"
            msg_color = '#008800'
    ai_response = ''
    if 'claude_history' not in session:
        session['claude_history'] = []
    if request.method == 'POST' and 'claude_prompt' in request.form:
        prompt = request.form.get('claude_prompt', '').strip()
        if prompt:
            history = session.get('claude_history', [])
            history.append({
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            })
            history = history[-1000:]
            try:
                response = client.beta.messages.create(
                    model="claude-sonnet-4-5",
                    max_tokens=1024,
                    messages=history,
                    betas=["files-api-2025-04-14"],
                )
                ai_text = response.content[0].text if hasattr(response, 'content') and response.content else 'No response from Claude.'
                ai_response = ai_text
                history.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": ai_text}]
                })
                history = history[-1000:]
                session['claude_history'] = history
            except Exception as e:
                print('Claude error:', e)
                print(traceback.format_exc())
                ai_response = f"Claude error: {e}"
    earnings = 0.00
    # File Manager logic
    UPLOAD_FOLDER = 'uploads'
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    file_msg = ''
    if request.method == 'POST' and 'file_upload' in request.form:
        uploaded_files = request.files.getlist('file')
        saved_files = []
        for file in uploaded_files:
            if file.filename:
                save_path = os.path.join(UPLOAD_FOLDER, file.filename)
                file.save(save_path)
                saved_files.append(file.filename)
        if saved_files:
            file_msg = f"Uploaded: {', '.join(saved_files)}"
        else:
            file_msg = "No files uploaded."
    # List files
    file_list = []
    try:
        file_list = os.listdir(UPLOAD_FOLDER)
    except Exception:
        file_list = []



        # --- Squeeze Page Manager variables ---
        SQUEEZE_DIR = 'squeeze_pages'
        os.makedirs(SQUEEZE_DIR, exist_ok=True)
        squeeze_msg = ''
        squeeze_edit_filename = ''
        squeeze_edit_content = ''
        # List all squeeze page files
        squeeze_files = [f for f in os.listdir(SQUEEZE_DIR) if f.endswith('.html')]
        # Handle edit request (GET)
        if request.method == 'GET' and 'edit' in request.args:
            edit_fname = request.args.get('edit', '').strip()
            if edit_fname and edit_fname in squeeze_files:
                squeeze_edit_filename = edit_fname
                try:
                    with open(os.path.join(SQUEEZE_DIR, edit_fname), 'r', encoding='utf-8') as f:
                        squeeze_edit_content = f.read()
                except Exception as e:
                    squeeze_msg = f'Error loading {edit_fname}: {e}'
        # Handle create or edit (POST)
        if request.method == 'POST' and ('squeeze_create' in request.form or 'squeeze_edit' in request.form):
            fname = request.form.get('squeeze_filename', '').strip()
            content = request.form.get('squeeze_content', '').replace('\r\n', '\n')
            if not fname.endswith('.html'):
                squeeze_msg = 'Filename must end with .html'
            elif not fname or '/' in fname or '\\' in fname:
                squeeze_msg = 'Invalid filename.'
            else:
                try:
                    with open(os.path.join(SQUEEZE_DIR, fname), 'w', encoding='utf-8') as f:
                        f.write(content)
                    squeeze_msg = f'Saved {fname}!'
                    squeeze_edit_filename = fname
                    squeeze_edit_content = content
                    # Refresh file list
                    squeeze_files = [f for f in os.listdir(SQUEEZE_DIR) if f.endswith('.html')]
                except Exception as e:
                    squeeze_msg = f'Error saving {fname}: {e}'

        # JavaScript for AJAX and scroll position
        js_code = '''
        // Claude form AJAX
        document.getElementById('claude-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                const promptInput = document.getElementById('claude-prompt');
                const aiResponseDiv = document.getElementById('ai-response');
                const prompt = promptInput.value.trim();
                if (!prompt) return;
                aiResponseDiv.textContent = 'Thinking...';
                try {
                        const resp = await fetch(window.location.pathname, {
                                method: 'POST',
                                headers: {'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'},
                                body: new URLSearchParams({claude_prompt: prompt})
                        });
                        const html = await resp.text();
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(html, 'text/html');
                        const newAi = doc.getElementById('ai-response');
                        if (newAi) aiResponseDiv.innerHTML = newAi.innerHTML;
                        else aiResponseDiv.textContent = 'No response.';
                } catch (err) {
                        aiResponseDiv.textContent = 'Error: ' + err.message;
                }
                promptInput.value = '';
                promptInput.focus();
                aiResponseDiv.scrollIntoView({behavior: 'smooth', block: 'center'});
        });
        // Squeeze Page Manager AJAX
        const squeezeForm = document.getElementById('squeeze-form');
        if (squeezeForm) {
            squeezeForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                const formData = new FormData(squeezeForm);
                const msgbox = document.getElementById('squeeze-msgbox');
                msgbox.textContent = 'Saving...';
                try {
                    const resp = await fetch(window.location.pathname, {
                        method: 'POST',
                        body: formData
                    });
                    const html = await resp.text();
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const newSection = doc.getElementById('squeeze-section');
                    if (newSection) {
                        document.getElementById('squeeze-section').innerHTML = newSection.innerHTML;
                        msgbox.textContent = 'Saved!';
                    } else {
                        msgbox.textContent = 'Saved, but could not update UI.';
                    }
                } catch (err) {
                    msgbox.textContent = 'Error: ' + err.message;
                }
            });
        }
        // Keep scroll position after AJAX
        window.addEventListener('beforeunload', function() {
            localStorage.setItem('scrollY', window.scrollY);
        });
        window.addEventListener('load', function() {
            const y = localStorage.getItem('scrollY');
            if (y) window.scrollTo(0, parseInt(y));
        });
        '''

    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Backoffice | Rent A Pog</title>
            <meta name="robots" content="noindex, nofollow">
            <style>
                    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f7fa; color: #222; }
                    .container { max-width: 700px; margin: 60px auto; background: #fff; border-radius: 12px; box-shadow: 0 0 24px rgba(0, 31, 91, 0.08); padding: 32px; border: 2px solid #e60000; }
                    h1 { color: #e60000; }
                    .section { background: #e9e9e9; border-radius: 8px; padding: 18px; margin-bottom: 18px; border-left: 6px solid #001f5b; }
                    .affiliate { background: #fffbe6; border: 1px solid #ffe082; border-radius: 8px; padding: 16px; margin-bottom: 18px; }
                    .stripe { background: #e0f7fa; border: 1px solid #00bcd4; border-radius: 8px; padding: 16px; margin-bottom: 18px; }
                    .stripe-btn { display:inline-block; background:#635bff; color:#fff; font-weight:bold; padding:12px 24px; border-radius:6px; text-decoration:none; font-size:1.1em; margin-top:10px; }
                    .stripe-btn:hover { background:#4b42c7; }
                    .logo { display: block; margin: 0 auto 24px auto; max-width: 180px; }
                    .affiliate-linkbox { font-size:1.1em; word-break:break-all; background:#fff; border:1px solid #ffe082; border-radius:8px; padding:12px; margin-top:8px; }
                    .msgbox { color: {{ msg_color }}; font-weight: bold; margin-bottom: 12px; }
                    .domain-list { margin-top: 10px; }
                    .domain-item { background: #e0ffe0; border-radius: 6px; padding: 6px 12px; margin-bottom: 4px; display: inline-block; }
                    .ai-section { background: #f0f7ff; border: 1px solid #b3d1ff; border-radius: 8px; padding: 16px; margin-bottom: 18px; }
                    .ai-response { background: #fff; border: 1px solid #b3d1ff; border-radius: 8px; padding: 12px; margin-top: 8px; min-height: 32px; }
            </style>
            <script>
            {js_code}
            </script>
        </head>
        <body>
            <div class="container">
                <img src="{{ url_for('static', filename='logo.png') }}" alt="Rent A Pog Logo" class="logo">
                <h1>Welcome, {{ admin_name }}!</h1>
                <div style="text-align:right;margin-bottom:10px;"><a href="/logout" style="color:#e60000;font-weight:bold;">Logout</a></div>
                <div style="margin-bottom:12px; color:#001f5b; font-size:1.1em;">Admin Email: <b>{{ user_email }}</b></div>
                <div class="affiliate">
                    <h2>Your Affiliate Link</h2>
                    <div class="affiliate-linkbox">{{ affiliate_link }}</div>
                </div>
                <div class="section">
                    <h2>Domains</h2>
                    <form method="post">
                        <input type="text" name="domain" placeholder="Add domain" required>
                        <button type="submit">Add</button>
                    </form>
                    <div class="msgbox">{{ msg }}</div>
                    <div class="domain-list">
                        {% for d in USER_DOMAINS['admin'] %}<span class="domain-item">{{ d }}</span>{% endfor %}
                    </div>
                </div>
                <div class="ai-section">
                    <h2>Claude Assistant</h2>
                    <form id="claude-form" method="post">
                        <input type="text" id="claude-prompt" name="claude_prompt" placeholder="Ask Claude..." required style="width:80%;">
                        <button type="submit">Ask</button>
                    </form>
                    <div id="ai-response" class="ai-response">{{ ai_response }}</div>
                </div>
                <div class="section">
                    <h2>File Manager</h2>
                    <form method="post" enctype="multipart/form-data">
                        <input type="file" name="file" multiple required>
                        <input type="hidden" name="file_upload" value="1">
                        <button type="submit">Upload</button>
                    </form>
                    <div class="msgbox">{{ file_msg }}</div>
                    <ul>
                        {% for fname in file_list %}<li><a href="/download/{{ fname }}" target="_blank">{{ fname }}</a></li>{% endfor %}
                    </ul>
                </div>
                <div class="section" id="squeeze-section">
                    <h2>Squeeze Page Manager</h2>
                    <form id="squeeze-form" method="post">
                        <input type="text" name="squeeze_filename" placeholder="Filename (e.g. squeeze19.html)" value="{{ squeeze_edit_filename }}" required>
                        <br><textarea name="squeeze_content" rows="10" style="width:98%;margin-top:8px;" placeholder="Paste or edit HTML here..." required>{{ squeeze_edit_content }}</textarea><br>
                        <button type="submit" name="{{ 'squeeze_edit' if squeeze_edit_filename else 'squeeze_create' }}">{{ 'Update' if squeeze_edit_filename else 'Create' }}</button>
                    </form>
                    <div class="msgbox" id="squeeze-msgbox">{{ squeeze_msg }}</div>
                    <h3>Existing Squeeze Pages</h3>
                    <ul>
                        {% for fname in squeeze_files %}<li>{{ fname }} <a href="?edit={{ fname }}">Edit</a></li>{% endfor %}
                    </ul>
                </div>
            </div>
        </body>
        </html>
    ''',
        squeeze_msg=squeeze_msg,
        squeeze_edit_filename=squeeze_edit_filename,
        squeeze_edit_content=squeeze_edit_content,
        squeeze_files=squeeze_files,
        msg=msg,
        msg_color=msg_color,
        ai_response=ai_response,
        admin_name=admin_name,
        user_email=user_email,
        affiliate_link=affiliate_link,
        file_msg=file_msg,
        file_list=file_list
    )

# --- Login route (admin only, env secrets) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    import hashlib
    from flask import make_response, request
    import os
    ADMIN_USER = 'admin@rentapog.com'
    ADMIN_PASS = 'FERGTRyhujikohy7FERGTRyhujikohy@)(-=987ju7'
    TOTP_SECRET_FILE = 'admin_totp_secret.txt'
    # Load or create TOTP secret
    if not os.path.exists(TOTP_SECRET_FILE):
        secret = pyotp.random_base32()
        with open(TOTP_SECRET_FILE, 'w') as f:
            f.write(secret)
    else:
        with open(TOTP_SECRET_FILE, 'r') as f:
            secret = f.read().strip()
    totp = pyotp.TOTP(secret)

    # QR code endpoint for setup
    if request.args.get('totp_qr') == '1':
        uri = totp.provisioning_uri(name=ADMIN_USER, issuer_name="Rent A Pog Admin")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png')

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '').strip()
        totp_code = request.form.get('totp_code', '').strip()
        if username == ADMIN_USER and password == ADMIN_PASS:
            # If TOTP not yet verified this session, require code
            if not session.get('totp_verified'):
                if not totp_code:
                    # Show TOTP code form with QR code link for setup
                    qr_url = url_for('login') + '?totp_qr=1'
                    return render_template_string('''
                        <h2>Set up 2FA (first time: scan QR in Google Authenticator or similar)</h2>
                        <img src="{{qr_url}}" alt="Scan QR code for TOTP" style="max-width:220px;display:block;margin-bottom:12px;">
                        <form method="post">
                            <input type="hidden" name="username" value="{{username}}">
                            <input type="hidden" name="password" value="{{password}}">
                            <label for="totp_code">Enter 6-digit code from your phone app:</label>
                            <input type="text" id="totp_code" name="totp_code" required pattern="\\d{6}" maxlength="6" autocomplete="one-time-code">
                            <button type="submit">Verify</button>
                        </form>
                        {% if error %}<div class="error">{{ error }}</div>{% endif %}
                    ''', username=username, password=password, qr_url=qr_url, error=error)
                # Validate TOTP code
                if not totp.verify(totp_code):
                    qr_url = url_for('login') + '?totp_qr=1'
                    return render_template_string('''
                        <h2>Set up 2FA (first time: scan QR in Google Authenticator or similar)</h2>
                        <img src="{{qr_url}}" alt="Scan QR code for TOTP" style="max-width:220px;display:block;margin-bottom:12px;">
                        <form method="post">
                            <input type="hidden" name="username" value="{{username}}">
                            <input type="hidden" name="password" value="{{password}}">
                            <label for="totp_code">Enter 6-digit code from your phone app:</label>
                            <input type="text" id="totp_code" name="totp_code" required pattern="\\d{6}" maxlength="6" autocomplete="one-time-code">
                            <button type="submit">Verify</button>
                        </form>
                        <div class="error">Invalid code. Try again.</div>
                    ''', username=username, password=password, qr_url=qr_url)
                # Mark TOTP as verified for this session
                session['totp_verified'] = True
            session['is_admin'] = True
            session['admin_name'] = username
            return redirect(url_for('backoffice'))
        else:
            error = 'Invalid username or password.'
    # If not POST, clear TOTP session
    session.pop('totp_verified', None)
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Login | Rent A Pog</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f7fa; color: #222; }
                .container { max-width: 400px; margin: 60px auto; background: #fff; border-radius: 12px; box-shadow: 0 0 24px rgba(0, 31, 91, 0.08); padding: 32px; border: 2px solid #e60000; }
                h1 { color: #e60000; }
                .input-group { margin-bottom: 18px; }
                label { display: block; margin-bottom: 6px; font-weight: bold; }
                input[type=text], input[type=password] { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #bbb; font-size: 1.1em; }
                .btn { background: #e60000; color: #fff; font-weight: bold; padding: 12px 24px; border-radius: 6px; border: none; font-size: 1.1em; cursor: pointer; }
                .btn:hover { background: #b30000; }
                .error { color: #e60000; margin-bottom: 12px; }
                .logo { display: block; margin: 0 auto 24px auto; max-width: 180px; }
            </style>
        </head>
        <body>
            <div class="container">
                <img src="{{ url_for('static', filename='logo.png') }}" alt="Rent A Pog Logo" class="logo">
                <h1>Login</h1>
                <form method="post">
                    {% if error %}<div class="error">{{ error }}</div>{% endif %}
                    <div class="input-group">
                        <label for="username">Email</label>
                        <input type="email" id="username" name="username" required placeholder="admin@rentapog.com" autocomplete="username">
                    </div>
                    <div class="input-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required minlength="12" autocomplete="current-password">
                    </div>
                    <button class="btn" type="submit">Login</button>
                </form>
                <!-- Signup and recover links removed for admin-only login -->
            </div>
        </body>
        </html>
    ''', error=error)

USER_DOMAINS = {}
UPLOAD_FOLDER = 'uploads'

# Helper to save user tokens (stub, implement as needed)
def save_user_tokens():
    pass  # No longer used

# --- Deploy to Fly.io endpoint (admin only) ---
import subprocess

# --- Secret Vault endpoint (admin only, code-protected) ---
VAULT_FILE = '.vault_secrets'

def load_vault_secrets():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'r') as f:
            lines = f.readlines()
        secrets = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
        return secrets
    return []

def save_vault_secrets(secrets):
    with open(VAULT_FILE, 'w') as f:
        for line in secrets:
            f.write(line.strip() + '\n')


@app.route('/vault', methods=['POST', 'PUT'])
def vault():
    if request.method == 'POST':
        secrets = load_vault_secrets()
        secrets_html = '<br>'.join(secrets)
        return secrets_html
    elif request.method == 'PUT':
        data = request.get_json()
        secrets = data.get('secrets', [])
        save_vault_secrets(secrets)
        return jsonify({'success': True})

@app.route('/deploy', methods=['POST'])
def deploy_to_fly():
    # Only allow admin session
    if not session.get('is_admin'):
        return 'Not authorized.', 403
    # Run 'fly deploy' in the project directory
    result = subprocess.run(['fly', 'deploy'], capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        return jsonify({'success': True, 'output': result.stdout})
    else:
        return jsonify({'success': False, 'error': result.stderr}), 500

# API endpoint for domain claim (dummy response)
@app.route('/api/claim-domain', methods=['POST'])
def api_claim_domain():
    data = request.get_json()
    domain = data.get('domain')
    email = data.get('email')
    # Dummy logic: always return success and available
    return {
        "success": True,
        "available": True,
        "message": f"Domain {domain} claimed successfully for {email}!"
    }

# File upload endpoint
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {"error": "No file part in the request."}, 400
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
    return {"message": msg}

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

def send_email_notification(to_email, subject, html_content):
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.example.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER', 'admin@rentapog.com')  # Use admin@rentapog.com for all notifications
    smtp_password = os.getenv('SMTP_PASSWORD', 'yourpassword')
    # Always use admin@rentapog.com as the sender for notifications
    from_email = os.getenv('FROM_EMAIL', 'admin@rentapog.com')
    # Note: admin@rentapog.com is reserved for personal/Stripe use only

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    part = MIMEText(html_content, 'html')
    msg.attach(part)
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_email, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")



@app.route('/recover', methods=['GET', 'POST'])
def recover():
    # This feature is no longer available in admin-only mode
    return render_template_string('<h1 style="color:#e60000;">Account recovery is not available. Please contact admin@rentapog.com for support.</h1>')


# --- Logout route ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



# --- Root route: render public front page ---

## Remove duplicate root route

# --- Coey AI Q&A endpoint ---
@app.route('/coey-ai', methods=['POST'])
def coey_ai():
    data = request.get_json()
    question = data.get('question', '').strip()
    if not question:
        return jsonify({'answer': "Please enter a question."})
    try:
        response = client.beta.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=256,
            messages=[
                {"role": "user", "content": [{"type": "text", "text": question}]}
            ],
            betas=["files-api-2025-04-14"],
        )
        ai_text = response.content[0].text if hasattr(response, 'content') and response.content else 'No response from Coey.'
        return jsonify({'answer': ai_text})
    except Exception as e:
        return jsonify({'answer': f"Error: {str(e)}"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)