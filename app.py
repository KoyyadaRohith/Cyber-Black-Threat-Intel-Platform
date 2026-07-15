import os
import hashlib
import ipaddress
import platform
import re
import secrets
import requests
from datetime import datetime, timedelta
from urllib.parse import urlencode
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, send_file

# Load configuration and services
from config import Config
import services.db_operations as db
import services.abuseipdb as abuse
import services.virustotal as vt
import services.whois_lookup as whois
import services.risk_scoring as risk
import services.threat_summary as summary
import services.recommendations as recs
import services.report_generator as report_gen
import services.ai_engine as ai_engine

# Initialize directories
Config.init_folders()

app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.globals['Config'] = Config

# Password hashing helpers
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def validate_password_strength(password):
    """Validate password strength: 8+ chars, uppercase, lowercase, digit, special char."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

# Parallelized IP scanners to eliminate synchronous latency bottlenecks
def fetch_ip_details_parallel(ip_address, ab_key, vt_key, use_mock):
    if use_mock:
        return (
            abuse.get_mock_abuse_data(ip_address),
            vt.get_mock_virustotal_data(ip_address),
            whois.get_mock_whois_data(ip_address)
        )
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_abuse = executor.submit(abuse.check_ip_abuse, ip_address, ab_key)
        future_vt = executor.submit(vt.check_ip_virustotal, ip_address, vt_key)
        future_whois = executor.submit(whois.get_whois_info, ip_address)
        
        abuse_data = future_abuse.result()
        vt_data = future_vt.result()
        whois_data = future_whois.result()
    return abuse_data, vt_data, whois_data

# Authentication check decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Authorization required. Please log in.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Notification helper — stores activity events in Supabase
def add_notification(icon, color, title, message):
    if 'username' in session:
        db.add_notification(session['username'], icon, color, title, message)
    
    if 'notifications' not in session:
        session['notifications'] = []
    notifs = session['notifications']
    notifs.insert(0, {
        'icon': icon,
        'color': color,
        'title': title,
        'message': message,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    session['notifications'] = notifs[:20]

# Context processor to inject standard global variables
@app.context_processor
def inject_globals():
    avatar_url = None
    if session.get('photo_url'):
        avatar_url = session['photo_url']
    elif 'username' in session:
        avatar_filename = f"{session['username']}.png"
        avatar_filepath = os.path.join(app.static_folder, 'uploads', 'avatars', avatar_filename)
        if os.path.exists(avatar_filepath):
            avatar_url = url_for('static', filename=f'uploads/avatars/{avatar_filename}')
            
    # Load dynamic notifications list from database
    notifications_list = []
    if 'username' in session:
        try:
            notifs = db.get_notifications(session['username'])
            for n in notifs:
                notifications_list.append({
                    'icon': n.get('icon', 'bell'),
                    'color': n.get('color', 'var(--primary)'),
                    'title': n.get('title', ''),
                    'message': n.get('message', ''),
                    'time': n.get('created_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                })
        except Exception:
            notifications_list = session.get('notifications', [])
    else:
        notifications_list = session.get('notifications', [])
        
    return {
        'time_now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'active_page': request.endpoint,
        'global_avatar_url': avatar_url,
        'notifications': notifications_list
    }

# Helper: Load settings state from Supabase
def get_user_settings():
    if 'username' in session:
        try:
            cfg = db.get_settings(session['username'])
            session['settings'] = cfg
            return cfg
        except Exception:
            pass
            
    if 'settings' not in session:
        session['settings'] = {}
        
    cfg = session['settings']
    # If keys are defined in Config but not in session, auto-inject them
    if Config.ABUSEIPDB_API_KEY.strip() and not cfg.get('abuseipdb_key'):
        cfg['abuseipdb_key'] = Config.ABUSEIPDB_API_KEY
        cfg['mock_mode'] = False
    if Config.VIRUSTOTAL_API_KEY.strip() and not cfg.get('virustotal_key'):
        cfg['virustotal_key'] = Config.VIRUSTOTAL_API_KEY
        cfg['mock_mode'] = False
        
    # Standard fallbacks
    if 'auto_watchlist_score' not in cfg:
        cfg['auto_watchlist_score'] = 75
    if 'mock_mode' not in cfg:
        has_keys = bool(Config.ABUSEIPDB_API_KEY.strip()) or bool(Config.VIRUSTOTAL_API_KEY.strip())
        cfg['mock_mode'] = not has_keys
        
    session['settings'] = cfg
    return session['settings']

# --- PUBLIC ROUTES ---

@app.route('/')
@app.route('/home')
def home():
    # Read database states to compile home page analytics
    history = db.get_history()
    watchlist = db.get_watchlist()
    
    total_scans = len(history)
    malicious_scans = len([r for r in history if r['classification'] == 'Malicious'])
    watchlist_count = len(watchlist)
    
    # Reports count: unique batch runs + manual scans
    total_reports = total_scans
    
    return render_template(
        'home.html',
        total_scans=total_scans,
        malicious_scans=malicious_scans,
        watchlist_count=watchlist_count,
        total_reports=total_reports
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        flashes = session.pop('_flashes', None)
        session.clear()
        if flashes:
            session['_flashes'] = flashes
        
    if request.method == 'POST':
        username_or_email = request.form['username'].strip()
        password = request.form['password']
        
        # Resolve username and email from input
        email = None
        user = None
        username = username_or_email
        
        if '@' in username_or_email:
            user = db.get_user_by_email(username_or_email)
            if user:
                email = user['email']
                username = user['username']
            else:
                email = username_or_email
                username = username_or_email.split('@')[0].replace('.', '_').replace('-', '_')
        else:
            user = db.get_user(username_or_email)
            if user:
                email = user['email']
                username = user['username']
            else:
                email = None
                username = username_or_email
                
        auth_res = None
        auth_pass = hash_password(password)
        
        if email:
            # Try 1: Sign in with the expected SHA256 hashed password
            try:
                from supabase import create_client
                client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
                auth_res = client.auth.sign_in_with_password({"email": email, "password": auth_pass})
                print(f"Supabase login succeeded with hashed password for {email}")
            except Exception as auth_err_hash:
                print(f"Supabase login with hashed password failed: {auth_err_hash}. Trying raw password...")
                
                # Try 2: Sign in with the raw password as a fallback
                try:
                    auth_res = client.auth.sign_in_with_password({"email": email, "password": password})
                    print(f"Supabase login succeeded with raw password fallback for {email}. Migrating password to hashed format...")
                    
                    # Automatically migrate password to hashed format in Supabase Auth
                    try:
                        db.update_password(username, auth_pass)
                        print(f"Successfully migrated password to hashed format for {username}")
                    except Exception as migration_err:
                        print(f"[WARNING] Failed to migrate password to hashed format: {migration_err}")
                except Exception as auth_err_raw:
                    print(f"Supabase login with raw password fallback failed: {auth_err_raw}")
            
            if auth_res and auth_res.user:
                # If public profile is missing, synchronize it now
                if not user:
                    user = db.sync_user_profile(auth_res.user.id, email, username, auth_pass)
                
                session['username'] = user['username'] if user else username
                session['email'] = email
                session['user_id'] = auth_res.user.id
                session['full_name'] = user.get('full_name', session['username'].title()) if user else username.title()
                session['mobile_number'] = user.get('mobile_number', '') if user else ''
                session['access_token'] = auth_res.session.access_token
                
                # Force-update mock_mode to False on login to enable live API checking
                cfg = db.get_settings(session['username'])
                if cfg and cfg.get('mock_mode') is not False:
                    cfg['mock_mode'] = False
                    db.save_settings(session['username'], cfg)
                
                add_notification('log-in', 'var(--color-safe)', 'Login Successful', f"Welcome back, Analyst {session['full_name']}.")
                flash(f"Welcome back, Analyst {session['full_name']}.", "success")
                return redirect(url_for('dashboard'))
                
        # Offline/Mock fallback for registration/testing (in case Supabase is completely unavailable/offline)
        if user and user['password_hash'] == hash_password(password):
            session['username'] = user['username']
            session['email'] = user['email']
            session['user_id'] = user.get('id')
            session['full_name'] = user.get('full_name', user['username'].title())
            session['mobile_number'] = user.get('mobile_number', '')
            add_notification('log-in', 'var(--color-safe)', 'Login Successful', f"Welcome back, Analyst {session['full_name']}.")
            flash(f"Welcome back, Analyst {session['full_name']}.", "success")
            return redirect(url_for('dashboard'))
            
        flash("Invalid credentials. Please check your username/email and password.", "error")
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        session.clear()
        
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        if not full_name:
            flash("Full name is required.", "error")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('register.html')
            
        if len(username) < 3 or len(password) < 6:
            flash("Username min 3 characters, Password min 6 characters.", "error")
            return render_template('register.html')
            
        hashed = hash_password(password)
        success, message = db.add_user(username, email, hashed, full_name=full_name, mobile_number=mobile_number)
        if success:
            flash("Access credentials generated successfully. Please sign in.", "success")
            return redirect(url_for('login'))
        else:
            flash(message, "error")
            
    return render_template('register.html')





@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Parse JSON or fallback to Form data
        data = request.get_json(silent=True) or request.form
        email = data.get('email', '').strip()
        new_password = data.get('new_password', '').strip()
        confirm_password = data.get('confirm_password', '').strip()
        
        print(f"[DEBUG] Forgot Password request received for email: '{email}'")
        
        if not email or not new_password or not confirm_password:
            print("[DEBUG] Validation failed: missing fields")
            return jsonify(success=False, message="All fields are required."), 400
            
        if new_password != confirm_password:
            print("[DEBUG] Validation failed: password mismatch")
            return jsonify(success=False, message="New passwords do not match."), 400
            
        # Server-side validation
        is_strong, strength_err = validate_password_strength(new_password)
        if not is_strong:
            print(f"[DEBUG] Validation failed: weak password: {strength_err}")
            return jsonify(success=False, message=strength_err), 400
            
        # Find user by email or username fallback
        print(f"[DEBUG] Performing email lookup via db.get_user_by_email for '{email}'")
        user = db.get_user_by_email(email)
        print(f"[DEBUG] db.get_user_by_email returned: {user}")
        if not user:
            print(f"[DEBUG] Falling back to username lookup via db.get_user for '{email}'")
            user = db.get_user(email)
            print(f"[DEBUG] db.get_user returned: {user}")
            
        # Direct Supabase client query inside route for verification
        if db.supabase:
            try:
                direct_res = db.supabase.table('users').select('*').ilike('email', email).execute()
                print(f"[DEBUG] Direct email query inside route returned data: {direct_res.data}")
                direct_user = db.supabase.table('users').select('*').ilike('username', email).execute()
                print(f"[DEBUG] Direct username query inside route returned data: {direct_user.data}")
            except Exception as direct_err:
                print(f"[DEBUG] Direct query inside route failed: {direct_err}")
        else:
            print("[DEBUG] db.supabase is None in route")
            
        print(f"[DEBUG] User lookup result: {user}")
        if not user:
            print(f"[DEBUG] User not found by email/username '{email}'")
            return jsonify(success=False, message="Invalid email or username, unable to reset password."), 400
            
        # Reset password directly
        success, msg = db.update_password(user['username'], hash_password(new_password))
        print(f"[DEBUG] Reset password operation outcome: success={success}, msg={msg}")
        if success:
            session.clear()  # Invalidate existing session
            return jsonify(success=True, message="Your account password has been reset successfully.")
        else:
            return jsonify(success=False, message="Invalid email or unable to reset password."), 500
            
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    try:
        from supabase import create_client
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
        client.auth.sign_out()
    except Exception:
        pass
    session.clear()
    return redirect(url_for('home'))

@app.route('/clear-notifications', methods=['POST'])
@login_required
def clear_notifications():
    db.clear_notifications(session['username'])
    session['notifications'] = []
    return jsonify(success=True)

# --- GOOGLE OAUTH ROUTES ---

@app.route('/coming-soon/google')
def coming_soon_google():
    """Renders the Google Sign-In Coming Soon placeholder page."""
    return render_template('coming_soon_google.html')

@app.route('/login/google')
def login_google():
    """Bypasses OAuth flow and redirects to Coming Soon screen (OAuth code preserved below)."""
    return redirect(url_for('coming_soon_google'))

    # Existing Google OAuth 2.0 flow using Supabase Auth (Can be re-enabled by removing the redirect above)
    try:
        from supabase import create_client
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
        
        redirect_uri = url_for('google_callback', _external=True)
        res = client.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": redirect_uri,
                "query_params": {
                    "prompt": "select_account"
                }
            }
        })
        
        # Save the code verifier in session so we can retrieve it in the callback (since Python Client generates one when flow_type="pkce")
        code_verifier = client.auth._storage.get_item(f"{client.auth._storage_key}-code-verifier")
        if code_verifier:
            session['oauth_code_verifier'] = code_verifier
            
        return redirect(res.url)
    except Exception as e:
        print(f"Error initiating Google OAuth: {e}")
        flash("Google Sign-In service is temporarily unavailable.", "error")
        return redirect(url_for('login'))


@app.route('/login/google/callback', methods=['GET', 'POST'])
def google_callback():
    """OAuth 2.0 callback endpoint: verifies profile info via Supabase Google OAuth and registers/logs in the user."""
    user_info = None
    
    # 1. Handle real Google Identity Services (GSI) POST request with JWT credential (if any client-side button triggers this)
    if request.method == 'POST' and 'credential' in request.form:
        credential = request.form['credential']
        try:
            from supabase import create_client
            client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
            auth_res = client.auth.sign_in_with_id_token({
                "provider": "google",
                "token": credential
            })
            if auth_res and auth_res.user:
                user_info = auth_res.user
        except Exception as e:
            print(f"Error signing in with Google ID token: {e}")
            flash("Google ID token verification failed.", "error")
            return redirect(url_for('login'))
            
    # 2. Handle redirect/code flow (GET)
    else:
        code = request.args.get('code')
        error_desc = request.args.get('error_description') or request.args.get('error')
        if error_desc:
            flash(f"Google authentication cancelled or failed: {error_desc}", "error")
            return redirect(url_for('login'))
            
        if not code:
            flash("Authorization code not returned by Google.", "error")
            return redirect(url_for('login'))
            
        code_verifier = session.pop('oauth_code_verifier', None)
        
        try:
            from supabase import create_client
            client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
            
            # Restore the code verifier to client storage so exchange_code_for_session can use it
            if code_verifier:
                client.auth._storage.set_item(f"{client.auth._storage_key}-code-verifier", code_verifier)
                
            auth_res = client.auth.exchange_code_for_session({
                "auth_code": code,
                "code_verifier": code_verifier
            })
            
            if auth_res and auth_res.user:
                user_info = auth_res.user
        except Exception as e:
            print(f"Error exchanging authorization code: {e}")
            flash("Failed to establish secure session with Google OAuth.", "error")
            return redirect(url_for('login'))

    if not user_info:
        flash("Authentication did not return user profile info.", "error")
        return redirect(url_for('login'))

    # Extract user identity attributes from Supabase user object
    email = user_info.email.strip()
    user_metadata = user_info.user_metadata or {}
    full_name = user_metadata.get('full_name', '') or user_metadata.get('name', '') or email.split('@')[0]
    picture = user_metadata.get('avatar_url', '') or user_metadata.get('picture', '')
    
    # Synchronize the user profile into Supabase users table (creates profile if not exists, updates last_login)
    sync_success = db.sync_google_user_profile(user_info.id, email, full_name, picture)
    if not sync_success:
        print("[WARNING] Failed to sync Google user profile with public schema users table.")

    # Retrieve updated user record from database
    user = db.get_user_by_email(email)
    
    # Fallback to metadata if public profiles insert failed or is slow
    username = user['username'] if user else email.split('@')[0].replace('.', '_').replace('-', '_')
    user_id = user['id'] if user else user_info.id
    display_name = user.get('full_name', full_name) if user else full_name
    
    # Establish Flask session state matching Supabase authenticated user
    session['username'] = username
    session['email'] = email
    session['user_id'] = user_id
    session['full_name'] = display_name
    session['mobile_number'] = user.get('mobile_number', '') if user else ''
    session['photo_url'] = user.get('profile_photo_url', picture) if user else picture
    
    add_notification('log-in', 'var(--color-safe)', 'Login Successful', f"Signed in via Google. Welcome back, Analyst {session['full_name']}.")
    flash(f"Signed in via Google. Welcome back, Analyst {session['full_name']}.", "success")
    return redirect(url_for('dashboard'))

# --- AUTHENTICATED PLATFORM PAGES ---

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    history = db.get_history(username)
    watchlist = db.get_watchlist(username)
    
    # Calculate widget states
    safe_scans = len([r for r in history if r['classification'].lower() == 'safe'])
    low_risk = len([r for r in history if r['classification'].lower() == 'low risk'])
    suspicious = len([r for r in history if r['classification'].lower() == 'suspicious'])
    high_risk = len([r for r in history if r['classification'].lower() == 'high risk'])
    malicious = len([r for r in history if r['classification'].lower() == 'malicious'])
    
    # Today's scans
    today_str = datetime.now().strftime('%Y-%m-%d')
    todays_scans = len([r for r in history if r['date'].startswith(today_str)])
    
    # Top Threat Countries and ASNs (excluding Safe / Safe-Low classification)
    from collections import Counter
    threat_countries = [r['country'] for r in history if r['classification'].lower() not in ['safe', 'low risk'] and r.get('country') and r['country'] != 'Unknown']
    top_countries = Counter(threat_countries).most_common(5)
    
    threat_asns = [f"{r['asn']} ({r['isp']})" for r in history if r['classification'].lower() not in ['safe', 'low risk'] and r.get('asn') and r['asn'] != 'Unknown']
    top_asns = Counter(threat_asns).most_common(5)
    
    stats = {
        'total_scans': len(history),
        'safe_scans': safe_scans,
        'low_risk_scans': low_risk,
        'suspicious_scans': suspicious,
        'high_risk_scans': high_risk,
        'malicious_scans': malicious,
        'todays_scans': todays_scans,
        'watchlist_count': len(watchlist),
        'total_reports': len(history),
        'top_countries': top_countries,
        'top_asns': top_asns
    }
    
    # Compile 7-day trend history
    labels = []
    counts = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append((datetime.now() - timedelta(days=i)).strftime('%b %d'))
        day_scans = len([r for r in history if r['date'].startswith(day)])
        counts.append(day_scans)
        
    trend_labels = labels
    trend_counts = counts
    
    # Threat Sources
    sources = [r.get('source', 'manual') for r in history]
    source_groups = []
    for s in sources:
        if s == 'manual':
            source_groups.append('Manual Scan')
        elif s.startswith('api_'):
            source_groups.append('API Ingestion')
        else:
            source_groups.append('Bulk File Ingest')
    source_distribution = Counter(source_groups).most_common(5)
    
    # Top Investigated IPs
    searched_ips = [r['ip'] for r in history]
    top_investigated_ips = Counter(searched_ips).most_common(5)
    
    # Watchlist Growth
    watchlist_labels = []
    watchlist_counts = []
    accumulated = 0
    sorted_wl = sorted(watchlist, key=lambda x: x.get('created_at', ''))
    for item in sorted_wl:
        accumulated += 1
        date_str = item.get('created_at', '')[:10]
        if date_str:
            try:
                date_str = datetime.strptime(date_str, '%Y-%m-%d').strftime('%b %d')
            except Exception:
                pass
        watchlist_labels.append(date_str)
        watchlist_counts.append(accumulated)
        
    if not watchlist_labels:
        watchlist_labels = [(datetime.now() - timedelta(days=i)).strftime('%b %d') for i in range(6, -1, -1)]
        watchlist_counts = [0, 0, 0, 0, 0, 0, len(watchlist)]
        
    recent_activity = history[:10]
    
    return render_template(
        'dashboard.html',
        stats=stats,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        source_distribution=source_distribution,
        top_investigated_ips=top_investigated_ips,
        watchlist_labels=watchlist_labels,
        watchlist_counts=watchlist_counts,
        recent_activity=recent_activity
    )

@app.route('/analytics')
@login_required
def threat_analytics():
    username = session['username']
    history = db.get_history(username)
    watchlist = db.get_watchlist(username)

    total_scans = len(history)
    threat_breakdown = {
        'Safe': len([r for r in history if r['classification'].lower() == 'safe']),
        'Low Risk': len([r for r in history if r['classification'].lower() == 'low risk']),
        'Suspicious': len([r for r in history if r['classification'].lower() == 'suspicious']),
        'High Risk': len([r for r in history if r['classification'].lower() == 'high risk']),
        'Malicious': len([r for r in history if r['classification'].lower() == 'malicious'])
    }
    total_watchlist = len(watchlist)
    total_reports = total_scans

    labels = []
    counts = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append((datetime.now() - timedelta(days=i)).strftime('%b %d'))
        counts.append(len([r for r in history if r['date'].startswith(day)]))

    recent_scans = sorted(history, key=lambda x: x['date'], reverse=True)[:8]
    all_scans = sorted(history, key=lambda x: x['date'], reverse=True)

    return render_template(
        'threat_analytics.html',
        total_scans=total_scans,
        threat_breakdown=threat_breakdown,
        total_watchlist=total_watchlist,
        total_reports=total_reports,
        trend_labels=labels,
        trend_counts=counts,
        recent_scans=recent_scans,
        all_scans=all_scans
    )

@app.route('/investigate', methods=['GET', 'POST'])
@login_required
def ip_investigation():
    details = None
    ip_address = request.args.get('ip_address', '').strip()
    error = None
    is_watched = False

    # If POST query or query parameter exists
    if request.method == 'POST':
        ip_address = request.form.get('ip_address', '').strip()

    # Optional: when explicitly requested, reuse last computed details for this IP
    # to prevent classification from changing after an action like Watchlist.
    use_cached = request.args.get('use_cached', '').strip() == '1'

    # If we have an IP, validate or reuse cached details
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)

            # Reuse cached investigation details when requested
            if use_cached:
                cached_map = session.get('last_investigation_details', {})
                cached = cached_map.get(ip_address)
                if cached:
                    details = cached

            # If no cached details were used/found, compute fresh
            if details is None:
                import time
                start_time = time.time()
                
                # Fetch config settings
                cfg = get_user_settings()
                use_mock = cfg.get('mock_mode', True)
                ab_key = cfg.get('abuseipdb_key') or Config.ABUSEIPDB_API_KEY
                vt_key = cfg.get('virustotal_key') or Config.VIRUSTOTAL_API_KEY
                abuse_data, vt_data, whois_data = fetch_ip_details_parallel(ip_address, ab_key, vt_key, use_mock)

                # Risk engines execution
                risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
                threat_sum = summary.generate_threat_summary(
                    ip_address, risk_profile['score'], risk_profile['classification'],
                    abuse_data, vt_data, whois_data
                )
                recs_list = recs.get_recommendations(risk_profile['classification'])
                
                duration_ms = int((time.time() - start_time) * 1000)

                details = {
                    'ip': ip_address,
                    'risk': risk_profile,
                    'abuse': abuse_data,
                    'vt': vt_data,
                    'whois': whois_data,
                    'summary': threat_sum,
                    'recommendations': recs_list,
                    'duration_ms': duration_ms,
                    'sources_used': 'AbuseIPDB, VirusTotal, WHOIS',
                    'actions_taken': 'Lookup Completed',
                    'notes': '',
                    'severity': 'Low',
                    'tags': ''
                }

                # Log results to History and retrieve DB record ID
                hist_record = db.add_history(
                    username=session['username'],
                    ip=ip_address,
                    country=whois_data.get('country'),
                    isp=whois_data.get('isp'),
                    asn=whois_data.get('asn'),
                    risk_score=risk_profile['score'],
                    classification=risk_profile['classification'],
                    threat_summary=threat_sum,
                    recommendations="; ".join([r['action'] for r in recs_list]),
                    abuse_score=abuse_data.get('abuse_score', 0),
                    vt_detections=vt_data.get('malicious_count', 0),
                    source='manual',
                    duration_ms=duration_ms,
                    sources_used='AbuseIPDB, VirusTotal, WHOIS',
                    actions_taken='Lookup Completed',
                    notes='',
                    severity='Low',
                    tags=''
                )
                
                if hist_record:
                    details['id'] = hist_record.get('id')

                # Persist computed details in session so subsequent actions (Watchlist)
                # can render the same classification.
                if 'last_investigation_details' not in session:
                    session['last_investigation_details'] = {}
                session['last_investigation_details'][ip_address] = details

                # Cache known malicious targets
                if risk_profile['classification'] == 'Malicious':
                    db.add_malicious_ip(ip_address, risk_profile['score'], 'Malicious', threat_sum)

                # Add notification for the search
                add_notification('search',
                    'var(--color-safe)' if risk_profile['classification'] == 'Safe' else 'var(--color-suspicious)' if risk_profile['classification'] == 'Suspicious' else 'var(--color-malicious)',
                    f"IP Investigated: {ip_address}",
                    f"Classification: {risk_profile['classification']} — Risk Score: {risk_profile['score']}/100")

                # Automation check: check if it matches auto-watchlist threshold
                auto_watchlist_score = int(cfg.get('auto_watchlist_score', 75))
                if risk_profile['score'] >= auto_watchlist_score:
                    db.add_to_watchlist(
                        ip_address, session['username'], risk_profile['score'],
                        risk_profile['classification'], "Auto-Watchlist: Score limit exceeded"
                    )

            # Check watchlist state (always reflect latest DB state)
            is_watched = db.is_in_watchlist(ip_address, session['username'])

        except ValueError:
            error = f"'{ip_address}' is not a valid IPv4 network address format."

    return render_template(
        'ip_investigation.html',
        ip_address=ip_address,
        details=details,
        error=error,
        is_watched=is_watched
    )

@app.route('/results/details/<ip_address>')
@login_required
def investigation_results(ip_address):
    # Route helper to redirect grid clicks straight into search diagnostics
    return redirect(url_for('ip_investigation', ip_address=ip_address))

@app.route('/file-upload', methods=['GET', 'POST'])
@login_required
def file_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file object selected.", "error")
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash("Filename cannot be blank.", "error")
            return redirect(request.url)
            
        if file:
            filename = file.filename
            ext = os.path.splitext(filename)[1].lower()
            
            if ext not in ['.csv', '.txt', '.log']:
                flash("File format not supported. Upload .csv, .txt, or log dumps.", "error")
                return redirect(request.url)
                
            # Read files data
            content = file.read().decode('utf-8', errors='ignore')
            
            # Extract IPs
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            unique_ips = list(set(ips))
            
            if not unique_ips:
                flash("No valid IP address targets identified in file structure.", "error")
                return redirect(request.url)
                
            # Cache target IPs in session for interactive load page
            session['parsed_ips'] = unique_ips
            session['upload_filename'] = filename
            add_notification('upload-cloud', 'var(--primary)', f'File Uploaded: {filename}', f'{len(unique_ips)} unique IPv4 targets extracted for analysis.')
            
            return redirect(url_for('analysis_pipeline'))
            
    return render_template('file_upload.html')

@app.route('/analysis')
@login_required
def analysis_pipeline():
    unique_ips = session.get('parsed_ips', [])
    filename = session.get('upload_filename', 'Unknown')
    return render_template('analysis.html', unique_ips=unique_ips, filename=filename)

@app.route('/api/analyze-single')
@login_required
def api_analyze_single():
    ip = request.args.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'Missing target'}), 400
        
    cfg = get_user_settings()
    use_mock = cfg.get('mock_mode', True)
    
    ab_key = cfg.get('abuseipdb_key') or Config.ABUSEIPDB_API_KEY
    vt_key = cfg.get('virustotal_key') or Config.VIRUSTOTAL_API_KEY
    abuse_data, vt_data, whois_data = fetch_ip_details_parallel(ip, ab_key, vt_key, use_mock)
    
    risk_profile = risk.calculate_risk_score(abuse_data, vt_data, whois_data)
    threat_sum = summary.generate_threat_summary(
        ip, risk_profile['score'], risk_profile['classification'],
        abuse_data, vt_data, whois_data
    )
    recs_list = recs.get_recommendations(risk_profile['classification'])
    
    # Save automatically to operational history archive (marked as bulk parsed)
    db.add_history(
        username=session['username'],
        ip=ip,
        country=whois_data.get('country'),
        isp=whois_data.get('isp'),
        asn=whois_data.get('asn'),
        risk_score=risk_profile['score'],
        classification=risk_profile['classification'],
        threat_summary=threat_sum,
        recommendations="; ".join([r['action'] for r in recs_list]),
        abuse_score=abuse_data.get('abuse_score', 0),
        vt_detections=vt_data.get('malicious_count', 0),
        source=session.get('upload_filename', 'bulk_upload')
    )
    
    if risk_profile['classification'] == 'Malicious':
        db.add_malicious_ip(ip, risk_profile['score'], 'Malicious', threat_sum)
        
    # Auto Watchlist Threshold check
    auto_watchlist_score = int(cfg.get('auto_watchlist_score', 75))
    if risk_profile['score'] >= auto_watchlist_score:
        db.add_to_watchlist(
            ip, session['username'], risk_profile['score'],
            risk_profile['classification'], "Auto-Watchlist Ingest Threshold Exceeded"
        )
        
    return jsonify({
        'ip': ip,
        'risk_score': risk_profile['score'],
        'classification': risk_profile['classification'],
        'country': whois_data.get('country'),
        'isp': whois_data.get('isp'),
        'asn': whois_data.get('asn')
    })

@app.route('/api/save-bulk-session', methods=['POST'])
@login_required
def save_bulk_session():
    data = request.get_json()
    filename = data.get('filename')
    results = data.get('results', [])
    
    # Unique batch code: filename + timestamp hash
    batch_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    batch_id = f"{filename}_{batch_timestamp}".replace('.', '_').replace(' ', '_')
    
    # We update the source values in history matching these results to index this batch
    for res in results:
        db.update_investigation_source(session['username'], res['ip'], filename, batch_id)
    
    # Return batch reference ID
    return jsonify({'batch_id': batch_id})

@app.route('/results')
@login_required
def results_console():
    batch_id = request.args.get('batch_id', '').strip()
    if not batch_id:
        flash("Operational batch ID not found.", "error")
        return redirect(url_for('file_upload'))
        
    # Query history for matches
    history = db.get_history(session['username'])
    results = [row for row in history if row['source'] == batch_id]
    
    if not results:
        flash("No diagnostic logs found matching batch ID.", "error")
        return redirect(url_for('file_upload'))
        
    # Calculate bulk metrics
    stats = {
        'total': len(results),
        'safe': len([r for r in results if r['classification'] == 'Safe']),
        'suspicious': len([r for r in results if r['classification'] == 'Suspicious']),
        'malicious': len([r for r in results if r['classification'] == 'Malicious'])
    }
    
    # Metadata details
    # Extract filename from batch_id (split before timestamp hash)
    parts = batch_id.split('_')
    filename = "_".join(parts[:-2]).replace('_csv', '.csv').replace('_txt', '.txt').replace('_log', '.log')
    
    file_metadata = {
        'filename': filename,
        'batch_id': batch_id
    }
    
    return render_template(
        'results.html',
        results=results,
        stats=stats,
        file_metadata=file_metadata,
        batch_id=batch_id
    )

@app.route('/watchlist')
@login_required
def watchlist():
    watchlist_data = db.get_watchlist(session['username'])
    return render_template('watchlist.html', watchlist=watchlist_data)

@app.route('/watchlist/add', methods=['POST'])
@login_required
def watchlist_add():
    ip = request.form['ip']
    score = request.form['risk_score']
    classification = request.form['classification']
    reason = request.form['reason']
    
    success, message = db.add_to_watchlist(ip, session['username'], score, classification, reason)
    if success:
        add_notification('eye', 'var(--color-suspicious)', f'Watchlist: {ip}', f'{ip} added to watchlist ({classification}).')
        flash(f"{ip} logged to watchlist register.", "success")
    else:
        flash(message, "error")
    # Redirect back to the investigation page while reusing cached details
    # so the displayed classification doesn't change after adding to watchlist.
    return redirect(url_for('ip_investigation', ip_address=ip, use_cached=1))

@app.route('/watchlist/delete', methods=['POST'])
@login_required
def watchlist_delete():
    ip = request.form['ip']
    success = db.remove_from_watchlist(ip, session['username'])
    if success:
        add_notification('eye-off', 'var(--text-muted)', f'Unwatched: {ip}', f'{ip} removed from watchlist surveillance.')
        flash(f"{ip} purged from watchlist surveillance.", "success")
    else:
        flash("Purge failed. IP address not found.", "error")
        
    # Redirect back to caller (watchlist panel or search console)
    referrer = request.referrer
    if referrer and 'watchlist' in referrer:
        return redirect(url_for('watchlist'))
    # Redirect back to the investigation page while reusing cached details
    # so the displayed classification doesn't change after watchlist actions.
    return redirect(url_for('ip_investigation', ip_address=ip, use_cached=1))



@app.route('/investigations/<investigation_id>/notes', methods=['POST'])
@login_required
def update_notes(investigation_id):
    username = session['username']
    notes = request.form.get('notes', '').strip()
    severity = request.form.get('severity', 'Low').strip()
    tags = request.form.get('tags', '').strip()
    actions_taken = request.form.get('actions_taken', '').strip() or None
    
    success = db.update_investigation_notes(investigation_id, username, notes, severity, tags, actions_taken)
    if success:
        flash("Analyst notes, tags, and severity logs updated.", "success")
    else:
        flash("Failed to update notes.", "error")
        
    return redirect(request.referrer or url_for('history'))

@app.route('/history')
@login_required
def history():
    history_data = db.get_history(session['username'])
    # Sort history by date descending
    history_sorted = sorted(history_data, key=lambda x: x['date'], reverse=True)
    return render_template('history.html', history=history_sorted)

@app.route('/reports')
@login_required
def reports():
    history = db.get_history(session['username'])
    
    # Pull unique bulk batch sources
    # Individual lookup sources are marked 'manual'
    unique_batches = list(set([r['source'] for r in history if r['source'] != 'manual']))
    
    report_list = []
    
    # 1. Populate individual reports
    # Every unique search log counts as an individual PDF download
    manual_searches = [r for r in history if r['source'] == 'manual']
    # Limit report cards to last 15 manual lookups to prevent visual clutter
    for row in sorted(manual_searches, key=lambda x: x['date'], reverse=True)[:15]:
        report_list.append({
            'type': 'individual',
            'title': f"Threat Reputation Report: {row['ip']}",
            'date': row['date'].split('T')[0] + " " + row['date'].split('T')[1][:5],
            'scope': f"{row['classification']} ({row['risk_score']}/100)",
            'ip': row['ip']
        })
        
    # 2. Populate bulk report items
    for batch in unique_batches:
        batch_rows = [r for r in history if r['source'] == batch]
        if batch_rows:
            # Extract filename from batch_id
            parts = batch.split('_')
            filename = "_".join(parts[:-2]).replace('_csv', '.csv').replace('_txt', '.txt').replace('_log', '.log')
            
            report_list.append({
                'type': 'bulk',
                'title': f"Bulk Ingestion Audit: {filename}",
                'date': batch_rows[0]['date'].split('T')[0] + " " + batch_rows[0]['date'].split('T')[1][:5],
                'scope': f"{len(batch_rows)} IP targets",
                'batch_id': batch
            })
            
    # Sort reports list by date descending
    report_list_sorted = sorted(report_list, key=lambda x: x['date'], reverse=True)
    
    return render_template('reports.html', reports=report_list_sorted)

@app.route('/reports/download/<report_id>')
@login_required
def download_report(report_id):
    username = session['username']
    history = db.get_history(username)
    
    # Case 1: Download individual report (TXT or PDF style HTML print page)
    if report_id.startswith('individual_'):
        ip = report_id.replace('individual_', '')
        # Find matching details in history
        row = next((r for r in history if r['ip'] == ip and r['source'] == 'manual'), None)
        if not row:
            # Try finding it in any bulk entries as fallback
            row = next((r for r in history if r['ip'] == ip), None)
            
        if not row:
            flash("Target log data not found.", "error")
            return redirect(url_for('reports'))
            
        # Reconstruct details dictionary from the database record row directly to bypass redundant network requests
        risk_profile = {
            'score': int(row.get('risk_score', 0)),
            'classification': row.get('classification', 'Safe')
        }
        
        try:
            abuse_score = int(row.get('abuse_score', 0))
        except (ValueError, TypeError):
            abuse_score = 0
            
        try:
            vt_detections = int(row.get('vt_detections', 0))
        except (ValueError, TypeError):
            vt_detections = 0
            
        abuse_data = {
            'ip': ip,
            'abuse_score': abuse_score,
            'total_reports': abuse_score,
            'last_reported_at': row.get('date'),
            'country_code': '',
            'country_name': row.get('country', 'Unknown'),
            'isp': row.get('isp', 'Unknown ISP'),
            'domain': row.get('isp', 'unknown').lower().split(',')[0].replace(' ', '') + '.com',
            'usage_type': 'Commercial',
            'is_mock': True
        }
        
        vt_data = {
            'ip': ip,
            'malicious_count': vt_detections,
            'suspicious_count': 0,
            'harmless_count': 90 - vt_detections,
            'undetected_count': 0,
            'total_engines': 90,
            'reputation_score': -vt_detections,
            'tags': [],
            'network': f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0/16" if '.' in ip else '',
            'asn': row.get('asn', '0'),
            'is_mock': True
        }
        
        whois_data = {
            'ip': ip,
            'country': row.get('country', 'Unknown'),
            'country_code': '',
            'city': 'Unknown',
            'region': 'Unknown',
            'isp': row.get('isp', 'Unknown'),
            'org': row.get('isp', 'Unknown'),
            'asn': row.get('asn', 'Unknown'),
            'asn_org': row.get('isp', 'Unknown'),
            'created_date': 'Unknown',
            'updated_date': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'timezone': 'UTC',
            'is_mock': True
        }
        
        recs_list = recs.get_recommendations(row.get('classification', 'Safe'))
        
        details = {
            'ip': ip,
            'risk': risk_profile,
            'abuse': abuse_data,
            'vt': vt_data,
            'whois': whois_data,
            'summary': row.get('threat_summary', ''),
            'recommendations': recs_list,
            'duration_ms': row.get('duration_ms', 0),
            'sources_used': row.get('sources_used', 'AbuseIPDB, VirusTotal, WHOIS'),
            'actions_taken': row.get('actions_taken', 'Lookup Completed'),
            'notes': row.get('notes', ''),
            'severity': row.get('severity', 'Low'),
            'tags': row.get('tags', '')
        }
        
        # Save individual HTML file to reports/pdf/
        html_content = report_gen.generate_html_print_individual(details)
        filename = f"MaliciousIP_Report_{ip}.html"
        file_path = Config.REPORTS_PDF / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        add_notification('file-down', 'var(--primary)', f'Report Exported: {ip}', f'Individual threat report downloaded for {ip}.')
        
        return send_file(
            file_path,
            mimetype="text/html",
            as_attachment=False,
            download_name=filename
        )
            
    # Case 2: Download bulk report formats
    elif report_id.startswith('bulk_'):
        parts = report_id.split('_')
        format_type = parts[-1]
        
        # Reconstruct batch ID
        if format_type in ['csv', 'txt']:
            batch_id = "_".join(parts[1:-1])
        else:
            batch_id = "_".join(parts[1:])
            format_type = 'pdf' # default print HTML page
            
        # Query matching database rows
        batch_results = [r for r in history if r['source'] == batch_id]
        if not batch_results:
            flash("Ingestion batch records not located.", "error")
            return redirect(url_for('reports'))
            
        # Extract filename
        parts_id = batch_id.split('_')
        filename = "_".join(parts_id[:-2])
        
        stats = {
            'total': len(batch_results),
            'safe': len([r for r in batch_results if r['classification'] == 'Safe']),
            'suspicious': len([r for r in batch_results if r['classification'] == 'Suspicious']),
            'malicious': len([r for r in batch_results if r['classification'] == 'Malicious'])
        }
        metadata = {'filename': filename}
        
        if format_type == 'csv':
            # Export CSV file download
            csv_data = report_gen.generate_csv_report(batch_results)
            fn = f"MaliciousIP_Batch_Report_{filename}.csv"
            file_path = Config.REPORTS_CSV / fn
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
                
            return send_file(
                file_path,
                mimetype="text/csv",
                as_attachment=True,
                download_name=fn
            )
            
        elif format_type == 'txt':
            
            # Export TXT summary download
            txt_data = report_gen.generate_txt_bulk(batch_results, metadata, stats)
            fn = f"MaliciousIP_Batch_Report_{filename}.txt"
            file_path = Config.REPORTS_TXT / fn
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
                
            return send_file(
                file_path,
                mimetype="text/plain",
                as_attachment=True,
                download_name=fn
            )
            
        else: # Print HTML window
            html_content = report_gen.generate_html_print_bulk(batch_results, metadata, stats)
            fn = f"MaliciousIP_Batch_Report_{filename}.html"
            file_path = Config.REPORTS_PDF / fn
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            return send_file(
                file_path,
                mimetype="text/html",
                as_attachment=False,
                download_name=fn
            )
            
    # Case 3: History & Watchlist general backups (CSV and TXT)
    elif report_id in ['history_csv', 'watchlist_csv', 'history_txt', 'watchlist_txt']:
        if report_id == 'history_csv':
            csv_data = report_gen.generate_csv_report(history)
            fn = "MaliciousIP_Investigation_History_Audit.csv"
            file_path = Config.REPORTS_CSV / fn
            mimetype = "text/csv"
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
        elif report_id == 'history_txt':
            txt_data = report_gen.generate_txt_history(history)
            fn = "MaliciousIP_Investigation_History_Audit.txt"
            file_path = Config.REPORTS_TXT / fn
            mimetype = "text/plain"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
        elif report_id == 'watchlist_csv':
            watchlist_data = db.get_watchlist(username)
            csv_data = report_gen.generate_csv_report(watchlist_data)
            fn = "MaliciousIP_Watchlist_Audit.csv"
            file_path = Config.REPORTS_CSV / fn
            mimetype = "text/csv"
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
        else: # watchlist_txt
            watchlist_data = db.get_watchlist(username)
            txt_data = report_gen.generate_txt_watchlist(watchlist_data)
            fn = "MaliciousIP_Watchlist_Audit.txt"
            file_path = Config.REPORTS_TXT / fn
            mimetype = "text/plain"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
            
        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=fn
        )
        
    flash("Report code not recognized.", "error")
    return redirect(url_for('reports'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.get_user(session['username'])
    if not user:
        flash("User profile not found. Please sign in again.", "error")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        full_name = data.get('full_name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        location = data.get('location', '').strip()
        role = data.get('role', '').strip()
        organization = data.get('organization', '').strip()
        bio = data.get('bio', '').strip()

        if not full_name or not username or not email:
            return jsonify(success=False, message="Full Name, Username, and Email are required."), 400

        old_username = session['username']
        success, message = db.update_user(
            current_username=old_username,
            full_name=full_name,
            username=username,
            email=email,
            location=location or "Hyderabad, Telangana, India",
            bio=bio,
            role=role or 'Threat Analyst',
            organization=organization or 'Cyber Black Threat Intel Platform'
        )
        if not success:
            return jsonify(success=False, message=message), 400

        if username and username != old_username:
            avatar_dir = os.path.join(app.static_folder, 'uploads', 'avatars')
            old_avatar = os.path.join(avatar_dir, f"{old_username}.png")
            new_avatar = os.path.join(avatar_dir, f"{username}.png")
            try:
                if os.path.exists(old_avatar):
                    os.replace(old_avatar, new_avatar)
            except OSError:
                pass

        session['username'] = username
        session['email'] = email
        session['full_name'] = full_name
        add_notification('user', 'var(--primary)', 'Profile Updated', f'Profile details saved for {full_name}.')

        updated_user = db.get_user(username)
        return jsonify(success=True, message=message, user={
            'full_name': updated_user.get('full_name', ''),
            'username': updated_user.get('username', ''),
            'email': updated_user.get('email', ''),
            'location': updated_user.get('location', ''),
            'role': updated_user.get('role', 'Threat Analyst'),
            'organization': updated_user.get('organization', 'Cyber Black Threat Intel Platform'),
            'created_at': updated_user.get('created_at', ''),
            'bio': updated_user.get('bio', '')
        })

    history = db.get_history(session['username'])
    watchlist = db.get_watchlist(session['username'])
    stats = {
        'total_scans': len(history),
        'watchlist_count': len(watchlist),
        'total_reports': len(history)
    }
    member_since = ''
    if user.get('created_at'):
        try:
            member_since = datetime.fromisoformat(user['created_at']).strftime('%B %d, %Y')
        except ValueError:
            member_since = user['created_at']

    return render_template('profile.html', user=user, stats=stats, member_since=member_since)

@app.route('/profile/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify(success=False, message="No image file provided."), 400
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify(success=False, message="Empty filename."), 400
        
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
        return jsonify(success=False, message="Supported formats: PNG, JPG, JPEG, GIF."), 400
        
    # Save file
    avatar_dir = os.path.join(app.static_folder, 'uploads', 'avatars')
    os.makedirs(avatar_dir, exist_ok=True)
    
    filename = f"{session['username']}.png"
    filepath = os.path.join(avatar_dir, filename)
    file.save(filepath)
    
    import time
    avatar_url = url_for('static', filename=f'uploads/avatars/{filename}') + f"?t={int(time.time())}"
    return jsonify(success=True, message="Profile picture updated successfully.", avatar_url=avatar_url)

@app.route('/api/settings/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json(silent=True) or request.form
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    confirm_password = data.get('confirm_password', '').strip()
    
    if not current_password or not new_password or not confirm_password:
        return jsonify(success=False, message="All password fields are required."), 400
        
    if new_password != confirm_password:
        return jsonify(success=False, message="New passwords do not match."), 400
        
    # Backend password strength validation
    is_strong, strength_err = validate_password_strength(new_password)
    if not is_strong:
        return jsonify(success=False, message=strength_err), 400
        
    user = db.get_user(session['username'])
    if not user:
        return jsonify(success=False, message="User profile not found."), 400
        
    password_correct = False
    
    # 1. Local password_hash check (if set)
    if user.get('password_hash') and user['password_hash'] == hash_password(current_password):
        password_correct = True
        
    # 2. Supabase Auth sign-in verification check as fallback/sync verification
    if not password_correct:
        try:
            from supabase import create_client
            client = create_client(Config.SUPABASE_URL, Config.SUPABASE_ANON_KEY)
            
            # Try 2.1: Sign in with the expected hashed password
            try:
                auth_res = client.auth.sign_in_with_password({"email": session['email'], "password": hash_password(current_password)})
                if auth_res and auth_res.user:
                    password_correct = True
            except Exception:
                # Try 2.2: Sign in with raw password fallback
                try:
                    auth_res = client.auth.sign_in_with_password({"email": session['email'], "password": current_password})
                    if auth_res and auth_res.user:
                        password_correct = True
                except Exception:
                    pass
        except Exception:
            pass
            
    if not password_correct:
        return jsonify(success=False, message="Current password is incorrect."), 400
        
    success, msg = db.update_password(session['username'], hash_password(new_password))
    if success:
        add_notification('key', 'var(--color-safe)', 'Password Changed', 'Your account password has been updated.')
        session.clear()  # Invalidate existing session
        return jsonify(success=True, message="Password updated successfully.")
    else:
        return jsonify(success=False, message=f"Failed to update password: {msg}"), 500

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    cfg = get_user_settings()
    
    if request.method == 'POST':
        # Update settings dict from form inputs
        for key, val in request.form.items():
            if key in ['mock_mode', 'email_alerts', 'desktop_notifications', 'include_whois', 'ai_enabled']:
                continue
            cfg[key] = val.strip()
            
        # Parse integers
        try:
            cfg['auto_watchlist_score'] = int(request.form.get('auto_watchlist_score', 75))
        except ValueError:
            cfg['auto_watchlist_score'] = 75
            
        # Parse boolean toggles
        cfg['mock_mode'] = cfg.get('mock_mode', True)
        cfg['email_alerts'] = 'email_alerts' in request.form
        cfg['desktop_notifications'] = 'desktop_notifications' in request.form
        cfg['include_whois'] = 'include_whois' in request.form
        cfg['ai_enabled'] = 'ai_enabled' in request.form
        
        session['settings'] = cfg
        db.save_settings(session['username'], cfg)
        
        # Verify if API keys are provided when mock mode is turned off
        if not cfg['mock_mode'] and not cfg.get('abuseipdb_key') and not cfg.get('virustotal_key'):
            cfg['mock_mode'] = True
            db.save_settings(session['username'], cfg) # Update DB too
            flash("Configurations updated. Mock mode enforced because API keys are blank.", "warning")
        else:
            flash("Console configurations committed.", "success")
        
        add_notification('settings', 'var(--primary)', 'Settings Updated', 'Console configurations saved successfully.')
        return redirect(url_for('settings'))
        
    return render_template('settings.html', settings=cfg)

# ============================================================
# V5.0 AI INTELLIGENCE LAYER ROUTES
# ============================================================

@app.route('/api/ai/analyze/<ip_address>')
@login_required
def ai_analyze(ip_address):
    """
    Async AI analysis endpoint — called by the browser after investigation loads.
    Returns JSON so the frontend can populate the AI panel without blocking the scan.
    """
    cfg = get_user_settings()
    
    if not cfg.get('ai_enabled', True):
        return jsonify({'disabled': True, 'message': 'AI Analysis is disabled in settings.'})
    
    # Find the most recent investigation row for this IP
    history = db.get_history(session['username'])
    row = next((r for r in history if r['ip'] == ip_address), None)
    
    if not row:
        return jsonify({'error': 'Investigation record not found. Run a scan first.'}), 404
    
    try:
        result = ai_engine.analyze_investigation(row, cfg)
        result['disclaimer'] = 'AI-generated analysis. Always verify findings before taking security actions.'
        return jsonify(result)
    except Exception as e:
        print(f"[AI ROUTE ERROR] analyze failed: {e}")
        return jsonify({'error': 'AI analysis temporarily unavailable.', 'fallback': True}), 500


@app.route('/api/ai/insights')
@login_required
def ai_insights():
    """Return AI-generated dashboard insight bullets as JSON."""
    cfg = get_user_settings()
    history = db.get_history(session['username'])
    try:
        bullets = ai_engine.generate_ai_insights(history, cfg)
        return jsonify({'insights': bullets})
    except Exception as e:
        print(f"[AI ROUTE ERROR] insights failed: {e}")
        return jsonify({'insights': ['AI insight generation temporarily unavailable.']})


@app.route('/api/ai/search', methods=['POST'])
@login_required
def ai_natural_search():
    """
    Natural Language Search — convert a plain English query into filtered investigation results.
    Examples: 'Show all malicious IPs this week' / 'Find investigations from Amazon ASN'
    """
    query = request.json.get('query', '').strip().lower() if request.is_json else request.form.get('query', '').strip().lower()
    
    if not query:
        return jsonify({'error': 'Query cannot be empty.'}), 400
    
    history = db.get_history(session['username'])
    
    # Parse the natural language query with rule-based + keyword extraction
    results = _nl_search_filter(query, history)
    
    return jsonify({
        'query': query,
        'count': len(results),
        'results': results[:50]  # cap at 50
    })


def _nl_search_filter(query, history):
    """
    Parse natural language query keywords into DB filter criteria.
    Supports: classification, country, ASN/ISP, time ranges, watchlist.
    """
    from datetime import datetime, timedelta
    
    filtered = list(history)
    
    # Time filters
    now = datetime.utcnow()
    if 'today' in query:
        filtered = [r for r in filtered if r['date'][:10] == now.strftime('%Y-%m-%d')]
    elif 'this week' in query or 'week' in query:
        week_ago = (now - timedelta(days=7)).strftime('%Y-%m-%d')
        filtered = [r for r in filtered if r['date'][:10] >= week_ago]
    elif 'this month' in query or 'month' in query:
        month_ago = (now - timedelta(days=30)).strftime('%Y-%m-%d')
        filtered = [r for r in filtered if r['date'][:10] >= month_ago]
    
    # Classification filters
    if 'malicious' in query:
        filtered = [r for r in filtered if r['classification'].lower() == 'malicious']
    elif 'high risk' in query:
        filtered = [r for r in filtered if r['classification'].lower() == 'high risk']
    elif 'suspicious' in query:
        filtered = [r for r in filtered if r['classification'].lower() == 'suspicious']
    elif 'low risk' in query:
        filtered = [r for r in filtered if r['classification'].lower() == 'low risk']
    elif 'safe' in query and 'not safe' not in query:
        filtered = [r for r in filtered if r['classification'].lower() == 'safe']
    
    # ISP / ASN filters — look for quoted strings or known provider names
    for keyword in ['amazon', 'google', 'microsoft', 'cloudflare', 'digitalocean', 'linode', 'ovh', 'hetzner', 'alibaba']:
        if keyword in query:
            filtered = [r for r in filtered if keyword in (r.get('isp') or '').lower() or keyword in (r.get('asn') or '').lower()]
            break
    
    # Country filter — detect "from [country]" pattern
    import re
    country_match = re.search(r'from\s+([a-z\s]+?)(?:\s+asn|\s+ip|\s+investig|$)', query)
    if country_match:
        country_term = country_match.group(1).strip()
        filtered = [r for r in filtered if country_term in (r.get('country') or '').lower()]
    
    return filtered


@app.route('/api/ai/report/<ip_address>')
@login_required
def ai_generate_report(ip_address):
    """
    Generate full AI SOC executive report for a specific IP and return it as plain text.
    """
    cfg = get_user_settings()
    history = db.get_history(session['username'])
    row = next((r for r in history if r['ip'] == ip_address), None)
    
    if not row:
        return jsonify({'error': 'No investigation record found for this IP.'}), 404
    
    try:
        analysis = ai_engine.analyze_investigation(row, cfg)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
        report_lines = [
            "=" * 70,
            "  CYBER BLACK THREAT INTEL PLATFORM — AI SOC EXECUTIVE REPORT",
            "=" * 70,
            f"  Generated : {timestamp}",
            f"  Target IP : {ip_address}",
            f"  AI Engine : {analysis.get('provider', 'Gemini')} / {analysis.get('model', 'gemini-1.5-flash')}",
            f"  Cached    : {'Yes' if analysis.get('cached') else 'No'}",
            "-" * 70,
            "",
            "1. EXECUTIVE SUMMARY",
            "-" * 70,
            analysis.get('summary', 'N/A'),
            "",
            "2. OVERALL THREAT ASSESSMENT",
            "-" * 70,
            analysis.get('assessment', 'N/A'),
            "",
            "3. KEY FINDINGS & IOC ANALYSIS",
            "-" * 70,
            analysis.get('findings', 'N/A'),
            "",
            "4. INDICATORS OF COMPROMISE EXPLANATION",
            "-" * 70,
            analysis.get('ioc_explanation', 'N/A'),
            "",
            "5. RECOMMENDED SECURITY POSTURE",
            "-" * 70,
            analysis.get('recommendation', 'N/A'),
            "",
            "6. SOC TEAM NEXT STEPS",
            "-" * 70,
            analysis.get('next_steps', 'N/A'),
            "",
            "-" * 70,
            f"  AI Confidence Score: {analysis.get('confidence_score', 85)}%",
            f"  Processing Time    : {analysis.get('processing_time_ms', 0)} ms",
            "-" * 70,
            "  ⚠  DISCLAIMER: AI-generated analysis. Always verify findings before",
            "     taking security actions.",
            "=" * 70,
        ]
        
        report_text = "\n".join(report_lines)
        return Response(
            report_text,
            mimetype='text/plain',
            headers={'Content-Disposition': f'attachment; filename=AI_SOC_Report_{ip_address.replace(".", "_")}.txt'}
        )
    except Exception as e:
        print(f"[AI ROUTE ERROR] report generation failed: {e}")
        return jsonify({'error': 'Report generation failed.'}), 500


# --- RUN APPLICATION ---

if __name__ == '__main__':
    print("[*] Starting Cyber Black Threat Intel Platform...")
    try:
        print(f"[*] Base Workspace: {Config.BASE_DIR}")
    except UnicodeEncodeError:
        print(f"[*] Base Workspace: {str(Config.BASE_DIR).encode('ascii', errors='replace').decode('ascii')}")
    app.run(port=Config.PORT, debug=Config.DEBUG)
