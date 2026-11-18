import os
import re
import hashlib
import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from database import init_db, get_db_connection

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = 'totalvirus_super_secret_key_change_in_production'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Optional: Set VIRUSTOTAL_API_KEY in environment for live VirusTotal API v3 lookups
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user_row:
        return User(id=user_row['id'], username=user_row['username'])
    return None

with app.app_context():
    init_db()

def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

def analyze_indicator(scan_type, target_value, sha256_digest):
    """Performs real VirusTotal API v3 lookup if API key is configured, otherwise deterministic heuristic threat analysis."""
    if VT_API_KEY:
        headers = {"x-apikey": VT_API_KEY}
        try:
            endpoint = None
            if scan_type in ('FILE', 'HASH'):
                endpoint = f"https://www.virustotal.com/api/v3/files/{sha256_digest}"
            elif scan_type == 'IP':
                endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target_value}"
            elif scan_type == 'DOMAIN':
                endpoint = f"https://www.virustotal.com/api/v3/domains/{target_value}"
            
            if endpoint:
                resp = requests.get(endpoint, headers=headers, timeout=8)
                if resp.status_code == 200:
                    data = resp.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values()) or 72
                    flagged = malicious + suspicious
                    risk_score = min(100, int((flagged / total) * 100)) if flagged > 0 else 0
                    verdict = "Malicious - Threat Intelligence Match" if malicious > 0 else (
                        "Suspicious - Heuristic Flag" if suspicious > 0 else "Clean - Verified by VirusTotal API"
                    )
                    return verdict, risk_score, f"{flagged}/{total}"
        except Exception:
            pass

    # Built-in Threat Intelligence Heuristics
    val_lower = target_value.lower()
    suspicious_keywords = ('malware', 'phish', 'trojan', 'exploit', 'ransom', 'botnet', 'c2', 'evil', 'hack', 'eicar')
    suspicious_exts = ('.exe', '.bat', '.vbs', '.ps1', '.scr', '.dll', '.cmd')
    high_risk_ips = ('185.220.', '45.33.32.', '192.0.2.', '198.51.100.')

    if any(k in val_lower for k in suspicious_keywords):
        return "Malicious - Threat Signature Detected", 88, "54/72"
    if scan_type == 'FILE' and val_lower.endswith(suspicious_exts):
        return "Suspicious - Executable Heuristic Flag", 62, "14/72"
    if scan_type == 'IP' and val_lower.startswith(high_risk_ips):
        return "Suspicious - Flagged ASN / C2 Node", 71, "19/72"
    if scan_type in ('URL', 'DOMAIN') and (val_lower.endswith(('.xyz', '.tk', '.top', '.pw')) or 'login-' in val_lower):
        return "Suspicious - High-Risk TLD / Phishing Pattern", 58, "11/72"

    return "Clean - No Threats Detected", 0, "0/72"

@app.route('/')
def index():
    conn = get_db_connection()
    recent_feed = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 5').fetchall()
    conn.close()
    return render_template('index.html', recent_feed=recent_feed)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Account created successfully. Welcome to TotalVirus!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another.', 'error')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db_connection()
        user_row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user_row and check_password_hash(user_row['password'], password):
            user = User(id=user_row['id'], username=user_row['username'])
            login_user(user)
            flash('Authentication verified. Session active.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Access denied.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 6').fetchall()
    total_scans = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    clean_scans = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_score = 0").fetchone()[0]
    flagged_scans = total_scans - clean_scans
    conn.close()
    stats = {
        'total': total_scans,
        'clean': clean_scans,
        'flagged': flagged_scans
    }
    return render_template('dashboard.html', scans=scans, stats=stats)

@app.route('/scanner', methods=['GET', 'POST'])
def scanner():
    active_tab = request.args.get('tab', 'FILE').upper()
    if active_tab not in ('FILE', 'URL', 'SEARCH', 'IP', 'DOMAIN', 'HASH'):
        active_tab = 'FILE'

    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'FILE').upper()
        
        if scan_type == 'FILE':
            if 'file' not in request.files or request.files['file'].filename == '':
                flash('Please select or drop a file to analyze.', 'error')
                return redirect(url_for('scanner', tab='FILE'))
            
            file = request.files['file']
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            file_size = format_size(os.path.getsize(filepath))
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            target_value = filename
        else:
            target_value = request.form.get('indicator_value', '').strip()
            if not target_value:
                flash(f'Please enter a valid {scan_type} indicator to analyze.', 'error')
                return redirect(url_for('scanner', tab=scan_type))
            
            file_size = 'IOC Indicator'
            if scan_type == 'HASH' and re.fullmatch(r'[a-fA-F0-9]{32,64}', target_value):
                file_hash = target_value.lower()
            else:
                file_hash = hashlib.sha256(target_value.encode('utf-8')).hexdigest()

        result, risk_score, engines_detected = analyze_indicator(scan_type, target_value, file_hash)
        status = "Completed"

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO scans (scan_type, target, file_size, file_hash, status, result, risk_score, engines_detected) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (scan_type, target_value, file_size, file_hash, status, result, risk_score, engines_detected)
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        flash(f'{scan_type} threat intelligence analysis completed.', 'success')
        return redirect(url_for('reports', scan_id=scan_id))

    return render_template('scanner.html', active_tab=active_tab)

@app.route('/reports/<int:scan_id>')
def reports(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not scan:
        flash('Scan report not found.', 'error')
        return redirect(url_for('index'))
    return render_template('reports.html', scan=scan)

@app.route('/history')
def history():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY timestamp DESC').fetchall()
    conn.close()
    return render_template('history.html', scans=scans)

if __name__ == '__main__':
    app.run(debug=True)
