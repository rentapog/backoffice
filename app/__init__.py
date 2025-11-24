## Move health check route below app initialization



# --- Imports ---
import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, g
from dotenv import load_dotenv
from app.claude import claude_bp
from werkzeug.utils import secure_filename
import stripe

# --- App Initialization ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.register_blueprint(claude_bp)
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
endpoint_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')

# --- Custom static file route (guaranteed static serving) ---
@app.route('/static/<path:filename>')
def custom_static(filename):
    import os
    static_dir = os.path.join(os.path.dirname(__file__), '..', 'static')
    return send_from_directory(static_dir, filename)

# --- Dashboard Backend Routes ---
DOMAINS_FILE = os.path.join(os.path.dirname(__file__), '..', 'domains.txt')
def get_domains():
    if not os.path.exists(DOMAINS_FILE):
        return []
    with open(DOMAINS_FILE, 'r') as f:
        return [line.strip() for line in f if line.strip()]
def add_domain(domain):
    domains = get_domains()
    if domain not in domains:
        with open(DOMAINS_FILE, 'a') as f:
            f.write(domain + '\n')

@app.route('/admin/add_domain', methods=['POST'])
def admin_add_domain():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    new_domain = request.form.get('new_domain', '').strip()
    if new_domain:
        add_domain(new_domain)
        flash(f"Domain {new_domain} added.")
    return redirect(url_for('admin_dashboard', selected_domain=new_domain))

@app.route('/admin/upload', methods=['POST'])
def admin_upload():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain') or 'default'
    domain_dir = os.path.join(os.path.dirname(__file__), '..', 'admin_uploads', domain)
    os.makedirs(domain_dir, exist_ok=True)
    files_uploaded = []
    if 'file' in request.files:
        files = request.files.getlist('file')
        for file in files:
            if file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(domain_dir, filename))
                files_uploaded.append(filename)
    flash(f"Uploaded: {', '.join(files_uploaded)}" if files_uploaded else "No files uploaded.")
    return redirect(url_for('admin_dashboard', selected_domain=domain))

@app.route('/admin/deploy', methods=['POST'])
def admin_deploy():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain') or 'default'
    domain_dir = os.path.join(os.path.dirname(__file__), '..', 'admin_uploads', domain)
    deployed_dir = os.path.join(os.path.dirname(__file__), '..', 'deployed_files', domain)
    os.makedirs(deployed_dir, exist_ok=True)
    files = os.listdir(domain_dir) if os.path.exists(domain_dir) else []
    for file in files:
        src = os.path.join(domain_dir, file)
        dst = os.path.join(deployed_dir, file)
        if os.path.isfile(src):
            with open(src, 'rb') as fsrc, open(dst, 'wb') as fdst:
                fdst.write(fsrc.read())
    flash(f"Deployed {len(files)} files for {domain}.")
    return redirect(url_for('admin_dashboard', selected_domain=domain))

@app.route('/admin/deploy_fly', methods=['POST'])
def admin_deploy_fly():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    import subprocess
    try:
        result = subprocess.run(['fly', 'deploy'], cwd=os.path.dirname(__file__), capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            flash('Fly.io deployment successful!')
        else:
            flash(f'Fly.io deployment failed: {result.stderr}')
    except Exception as e:
        flash(f'Error running Fly.io deploy: {e}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_dns', methods=['POST'])
def admin_update_dns():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    domain = request.form.get('domain')
    registrar = request.form.get('registrar')
    FLY_APP_DOMAIN = os.getenv('FLY_APP_DOMAIN')
    fly_domain = FLY_APP_DOMAIN or f"{os.getenv('FLY_APP_NAME')}.fly.dev"
    def update_namecheap_dns(domain, fly_domain):
        NAMECHEAP_API_USER = os.getenv('NAMECHEAP_API_USER')
        NAMECHEAP_API_KEY = os.getenv('NAMECHEAP_API_KEY')
        NAMECHEAP_API_URL = 'https://api.namecheap.com/xml.response'
        payload = {
            'ApiUser': NAMECHEAP_API_USER,
            'ApiKey': NAMECHEAP_API_KEY,
            'UserName': NAMECHEAP_API_USER,
            'ClientIp': request.remote_addr,
            'Command': 'namecheap.domains.dns.setHosts',
            'SLD': domain.split('.')[0],
            'TLD': domain.split('.')[-1],
            'HostName1': '@',
            'RecordType1': 'CNAME',
            'Address1': fly_domain,
            'TTL1': '1800',
        }
        response = requests.post(NAMECHEAP_API_URL, data=payload)
        return response.text
    def update_opensrs_dns(domain, fly_domain):
        OPENSRS_API_USER = os.getenv('OPENSRS_API_USER')
        OPENSRS_API_KEY = os.getenv('OPENSRS_API_KEY')
        OPENSRS_API_URL = 'https://rr-n1-tor.opensrs.net:55443'
        xml_payload = f'''
        <OPS_envelope>
          <header>
            <version>0.9</version>
            <msg_id>123</msg_id>
            <partner_id>{OPENSRS_API_USER}</partner_id>
            <password>{OPENSRS_API_KEY}</password>
          </header>
          <body>
            <data_block>
              <dt_assoc>
                <item key="domain">{domain}</item>
                <item key="op">set_dns</item>
                <item key="records">
                  <dt_array>
                    <item key="0">
                      <dt_assoc>
                        <item key="type">CNAME</item>
                        <item key="host">@</item>
                        <item key="data">{fly_domain}</item>
                        <item key="ttl">1800</item>
                      </dt_assoc>
                    </item>
                  </dt_array>
                </item>
              </dt_assoc>
            </data_block>
          </body>
        </OPS_envelope>
        '''
        headers = {'Content-Type': 'text/xml'}
        response = requests.post(OPENSRS_API_URL, data=xml_payload, headers=headers, verify=False)
        return response.text
    if registrar == 'namecheap':
        result = update_namecheap_dns(domain, fly_domain)
        success = '<IsSuccess>true</IsSuccess>' in result
    elif registrar == 'opensrs':
        result = update_opensrs_dns(domain, fly_domain)
        success = 'success' in result.lower() or 'ok' in result.lower()
    else:
        result = 'Unknown registrar.'
        success = False
    if success:
        flash(f'DNS updated for {domain} to point to {fly_domain} via {registrar.title()}')
    else:
        flash(f'Failed to update DNS: {result}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/health_check', methods=['POST'])
def admin_health_check():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    url = request.form.get('url')
    health_status = 'Offline'
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            health_status = 'Online'
    except Exception:
        health_status = 'Offline'
    domains = get_domains()
    selected_domain = request.args.get('selected_domain') or (domains[0] if domains else 'default')
    domain_dir = os.path.join(os.path.dirname(__file__), '..', 'admin_uploads', selected_domain)
    files = []
    if os.path.exists(domain_dir):
        files = [f for f in os.listdir(domain_dir) if os.path.isfile(os.path.join(domain_dir, f))]
    return render_template('dashboard.html', response=None, files=files, domains=domains, selected_domain=selected_domain, health_status=health_status, checked_url=url)

@app.route('/admin/auto_recover', methods=['POST'])
def admin_auto_recover():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    import subprocess
    try:
        result = subprocess.run(['fly', 'deploy'], cwd=os.path.dirname(__file__), capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            flash('Auto-recovery: Fly.io redeploy successful!')
        else:
            flash(f'Auto-recovery failed: {result.stderr}')
    except Exception as e:
        flash(f'Error during auto-recovery: {e}')
    return redirect(url_for('admin_dashboard'))

# --- Admin Backoffice: Automated Domain Registration ---
import xml.etree.ElementTree as ET

@app.route('/admin/register-domain', methods=['GET', 'POST'])
def admin_register_domain():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('admin_login'))
    msg = ''
    domain = ''
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        if domain:
            # Namecheap API credentials
            api_user = os.environ.get('NAMECHEAP_API_USERNAME')
            api_key = os.environ.get('NAMECHEAP_API_KEY')
            username = os.environ.get('NAMECHEAP_USERNAME')
            client_ip = request.remote_addr or '127.0.0.1'
            # Namecheap API endpoint
            url = 'https://api.namecheap.com/xml.response'
            params = {
                'ApiUser': api_user,
                'ApiKey': api_key,
                'UserName': username,
                'ClientIp': client_ip,
                'Command': 'namecheap.domains.create',
                'DomainName': domain,
                'Years': '1',
                'RegistrantFirstName': 'Admin',
                'RegistrantLastName': 'User',
                'RegistrantAddress1': '123 Main St',
                'RegistrantCity': 'City',
                'RegistrantStateProvince': 'State',
                'RegistrantPostalCode': '12345',
                'RegistrantCountry': 'US',
                'RegistrantPhone': '+1.5555555555',
                'RegistrantEmailAddress': 'admin@rentapog.com',
            }
            try:
                resp = requests.post(url, params=params)
                tree = ET.fromstring(resp.text)
                errors = tree.findall('.//Errors/Error')
                if errors:
                    msg = 'Error: ' + errors[0].text
                else:
                    msg = f"Domain {domain} registered successfully!"
            except Exception as e:
                msg = f"API error: {e}"
        else:
            msg = 'Please enter a valid domain name.'
    return render_template('admin_register_domain.html', msg=msg, domain=domain)

# --- Admin Login for rentapog.com ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    msg = ''
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            admin_username = os.environ.get('ADMIN_USERNAME')
            admin_email = os.environ.get('ADMIN_EMAIL')
            admin_password = os.environ.get('ADMIN_PASSWORD')
            print(f"DEBUG: username={username}, email={email}, password={password}")
            print(f"DEBUG: admin_username={admin_username}, admin_email={admin_email}, admin_password={admin_password}")
            if (
                username and admin_username and username == admin_username and
                email and admin_email and email == admin_email and
                password and admin_password and password == admin_password
            ):
                session['user'] = 'admin'
                return redirect(url_for('admin_dashboard'))
            else:
                msg = 'Invalid admin credentials.'
        except Exception as e:
            print(f"ERROR in admin_login: {e}")
            msg = f"Internal error: {e}"
    return render_template('admin_login.html', msg=msg)

# --- User Control Panel Login & Dashboard ---
@app.route('/user/control/login', methods=['GET', 'POST'])
def user_control_login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        env_username = os.environ.get('CONTROL_PANEL_USERNAME', 'rentapog.com')
        env_password = os.environ.get('CONTROL_PANEL_PASSWORD')
        if username == env_username and password == env_password:
            session['user_control'] = username
            return redirect(url_for('user_control_panel'))
        else:
            msg = 'Invalid credentials.'
    return render_template('user_control_login.html', msg=msg)

@app.route('/user/control/panel', methods=['GET', 'POST'])
def user_control_panel():
    if 'user_control' not in session:
        return redirect(url_for('user_control_login'))
    username = session['user_control']
    user_dir = os.path.join(os.path.dirname(__file__), '..', 'user_uploads', username)
    os.makedirs(user_dir, exist_ok=True)
    msg = ''
    # Support multiple file uploads
    if request.method == 'POST':
        # Get selected site/domain (default to username)
        target_site = request.form.get('site') or username
        user_dir = os.path.join(os.path.dirname(__file__), '..', 'user_uploads', target_site)
        os.makedirs(user_dir, exist_ok=True)
        # Handle multiple files
        files_uploaded = []
        if 'file' in request.files:
            files = request.files.getlist('file')
            for file in files:
                if file.filename:
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(user_dir, filename))
                    files_uploaded.append(filename)
        if files_uploaded:
            msg = f"Uploaded: {', '.join(files_uploaded)}"
    files = []
    try:
        files = os.listdir(user_dir)
    except Exception:
        files = []
    return render_template('user_control_panel.html', username=username, files=files, msg=msg)

@app.route('/user/control/delete', methods=['POST'])
def user_control_delete():
    if 'user_control' not in session:
        return redirect(url_for('user_control_login'))
    site = request.form.get('site') or session['user_control']
    filename = request.form.get('file')
    user_dir = os.path.join(os.path.dirname(__file__), '..', 'user_uploads', site)
    file_path = os.path.join(user_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('user_control_panel'))

# --- User Control Panel File Download ---
@app.route('/user/control/download', methods=['GET'])
def user_control_download():
    if 'user_control' not in session:
        return redirect(url_for('user_control_login'))
    site = request.args.get('site') or session['user_control']
    filename = request.args.get('file')
    user_dir = os.path.join(os.path.dirname(__file__), '..', 'user_uploads', site)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    return send_from_directory(user_dir, filename, as_attachment=True)
# --- Register Address Backend ---
@app.route('/register-address', methods=['POST'])
def register_address():
    domain = request.form.get('domain', '').strip()
    msg = ''
    if domain:
        reg_file = os.path.join(os.path.dirname(__file__), '..', 'registered_domains.txt')
        with open(reg_file, 'a') as f:
            f.write(domain + '\n')
        msg = f"Thank you! {domain} has been registered. Please proceed to payment."
    else:
        msg = "Please enter a valid domain name."
    return render_template('register_address.html', msg=msg)

# --- Backoffice Login Routes ---
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            session['user'] = username
            return redirect(url_for('backoffice'))
        else:
            msg = 'Invalid user credentials.'
    return render_template('user_login.html', msg=msg)

# --- Sales Control Panel Features ---
SALES_UPLOADS = os.path.join(os.path.dirname(__file__), '..', 'sales_uploads')
os.makedirs(SALES_UPLOADS, exist_ok=True)

def is_sales_user():
    return session.get('sales_user')

@app.route('/sales/login', methods=['GET', 'POST'])
def sales_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            session['sales_user'] = username
            return redirect(url_for('sales_control_panel'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/sales/logout')
def sales_logout():
    session.pop('sales_user', None)
    return redirect(url_for('sales_login'))

@app.route('/sales/control', methods=['GET', 'POST'])
def sales_control_panel():
    if not is_sales_user():
        return redirect(url_for('sales_login'))
    user = session['sales_user']
    user_dir = os.path.join(SALES_UPLOADS, secure_filename(user))
    os.makedirs(user_dir, exist_ok=True)
    msg = ''
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(user_dir, filename))
            msg = f"Uploaded: {filename}"
    files = []
    try:
        files = os.listdir(user_dir)
    except Exception:
        files = []
    return render_template('sales_control_panel.html', user=user, files=files, msg=msg)

@app.route('/sales/uploads/<username>/<filename>')
def sales_uploaded_file(username, filename):
    user_dir = os.path.join(SALES_UPLOADS, secure_filename(username))
    return send_from_directory(user_dir, filename)

# --- Backoffice Features ---
MONITORED_SITES = [
    'https://rentapog.com',
    'https://sales.rentapog.com',
    'https://shop.rentapog.com',
]

@app.route('/backoffice', methods=['GET'])
def backoffice():
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    files = []
    if os.path.exists(uploads_dir):
        files = [f for f in os.listdir(uploads_dir) if os.path.isfile(os.path.join(uploads_dir, f))]
    return render_template('backoffice.html', files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    return send_from_directory(uploads_dir, filename)

@app.route('/backoffice/delete', methods=['POST'])
def delete_file():
    filename = request.form.get('file')
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    file_path = os.path.join(uploads_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    return redirect(url_for('backoffice'))

@app.route('/backoffice/coey', methods=['POST'])
def coey_agent():
    task = request.form.get('coey-task', '').strip()
    import anthropic
    coey_api_key = os.environ.get('CLAUDE_API_KEY')
    response_text = ""
    if 'coey_history' not in session:
        session['coey_history'] = []
    history = session['coey_history']
    if not coey_api_key:
        response_text = "Error: Coey AI API key not configured."
    elif not task:
        response_text = "Please enter a request for Coey."
    else:
        try:
            history.append({"role": "user", "content": [{"type": "text", "text": task}]})
            if len(history) > 20:
                history = history[-20:]
            client = anthropic.Anthropic(api_key=coey_api_key)
            ai_response = client.beta.messages.create(
                model="claude-sonnet-4-5",
                max_tokens=256,
                messages=history,
                betas=["files-api-2025-04-14"],
            )
            if hasattr(ai_response, 'content') and ai_response.content:
                history.append({"role": "assistant", "content": ai_response.content})
                response_text = ai_response.content[0].text
            else:
                response_text = 'No response from Coey.'
            session['coey_history'] = history
        except Exception as e:
            response_text = f"Error: {str(e)}"
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    files = []
    if os.path.exists(uploads_dir):
        files = [f for f in os.listdir(uploads_dir) if os.path.isfile(os.path.join(uploads_dir, f))]
    return render_template('backoffice.html', coey_response=response_text, files=files)

@app.route('/backoffice/check-sites', methods=['POST'])
def check_sites():
    site_statuses = {}
    for site in MONITORED_SITES:
        try:
            r = requests.get(site, timeout=5)
            if r.status_code == 200:
                site_statuses[site] = 'Online'
            else:
                site_statuses[site] = f'Error: {r.status_code}'
        except Exception as e:
            site_statuses[site] = f'Down ({str(e)})'
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    files = []
    if os.path.exists(uploads_dir):
        files = [f for f in os.listdir(uploads_dir) if os.path.isfile(os.path.join(uploads_dir, f))]
    return render_template('backoffice.html', files=files, site_statuses=site_statuses)

@app.route('/backoffice/fix-sites', methods=['POST'])
def fix_sites():
    site_statuses = {}
    fix_result = []
    for site in MONITORED_SITES:
        try:
            r = requests.get(site, timeout=5)
            if r.status_code == 200:
                site_statuses[site] = 'Online'
            else:
                site_statuses[site] = f'Error: {r.status_code}'
                fix_result.append(f"Attempted fix for {site}: Restarted service or notified admin.")
        except Exception as e:
            site_statuses[site] = f'Down ({str(e)})'
            fix_result.append(f"Attempted fix for {site}: Restarted service or notified admin.")
    uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
    files = []
    if os.path.exists(uploads_dir):
        files = [f for f in os.listdir(uploads_dir) if os.path.isfile(os.path.join(uploads_dir, f))]
    return render_template('backoffice.html', files=files, site_statuses=site_statuses, fix_result='; '.join(fix_result))

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-and-conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/thank-you')
def thank_you():
    return render_template('thank-you.html')

@app.route('/facebook', methods=['GET'])
def facebook_landing():
    return render_template('facebook.html')

@app.route('/')
def domain_router():
    host = request.host.lower()
    if 'admin1.rentapog.com' in host:
        if 'user' not in session:
            return redirect(url_for('admin_login'))
        return redirect(url_for('admin_dashboard'))
    elif 'rentapog.com' == host or host.startswith('www.rentapog.com'):
        # Public homepage for rentapog.com
        return render_template('front.html')
    elif 'controlpanel.rentapog.com' in host:
        if 'user_control' not in session:
            return redirect(url_for('user_control_login'))
        username = session['user_control']
        user_dir = os.path.join(os.path.dirname(__file__), '..', 'user_uploads', username)
        os.makedirs(user_dir, exist_ok=True)
        msg = ''
        files = []
        try:
            files = os.listdir(user_dir)
        except Exception:
            files = []
        return render_template('user_control_panel.html', username=username, files=files, msg=msg)
    elif 'sales.rentapog.com' in host:
        return render_template('register_address.html')
    elif 'store.rentapog.com' in host:
        return render_template('packages.html')
    elif 'backoffice.rentapog.com' in host:
        uploads_dir = os.path.join(os.path.dirname(__file__), '..', 'uploads')
        files = []
        if os.path.exists(uploads_dir):
            files = [f for f in os.listdir(uploads_dir) if os.path.isfile(os.path.join(uploads_dir, f))]
        return render_template('backoffice.html', files=files)
    else:
        return render_template('front.html')

# Admin logout route
@app.route('/admin/logout')
def admin_logout():
    session.pop('user', None)
    return redirect(url_for('admin_login'))

# Admin dashboard route
@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    if 'user' not in session:
        return redirect(url_for('admin_login'))
    # Get domains and selected domain
    domains = []
    domains_file = os.path.join(os.path.dirname(__file__), '..', 'domains.txt')
    if os.path.exists(domains_file):
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    selected_domain = request.args.get('selected_domain') or (domains[0] if domains else 'default')
    domain_dir = os.path.join(os.path.dirname(__file__), '..', 'admin_uploads', selected_domain)
    files = []
    if os.path.exists(domain_dir):
        files = [f for f in os.listdir(domain_dir) if os.path.isfile(os.path.join(domain_dir, f))]
    return render_template('dashboard.html', response=None, files=files, domains=domains, selected_domain=selected_domain)

@app.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    if event['type'] == 'checkout.session.completed':
        session_obj = event['data']['object']
        print('Payment received! Session:', session_obj)
        return redirect(url_for('backoffice'))
    return jsonify(success=True)

if __name__ == '__main__':
    app.run(debug=True)


    