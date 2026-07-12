import os
from datetime import datetime

# Initialize Supabase Client
supabase = None
try:
    from supabase import create_client, Client
    supabase_url = os.environ.get("SUPABASE_URL", "")
    supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
    if supabase_url and supabase_key and "your-supabase-project" not in supabase_url:
        supabase = create_client(supabase_url, supabase_key)
except ImportError:
    pass

def _robust_insert(table_name, payload):
    """Inserts a record into a table, automatically removing columns that don't exist in the schema."""
    import re
    while True:
        try:
            res = supabase.table(table_name).insert(payload).execute()
            return True, res
        except Exception as e:
            err_msg = str(e)
            if "PGRST204" in err_msg:
                match = re.search(r"Could not find the '([^']+)' column", err_msg)
                if match:
                    failed_col = match.group(1)
                    if failed_col in payload:
                        print(f"[WARNING] Column '{failed_col}' not found in table '{table_name}'. Removing from payload and retrying.")
                        del payload[failed_col]
                        continue
            return False, e

def _robust_update(table_name, payload, row_id):
    """Updates a record, automatically removing columns that don't exist in the schema."""
    import re
    while True:
        try:
            res = supabase.table(table_name).update(payload).eq('id', row_id).execute()
            return True, res
        except Exception as e:
            err_msg = str(e)
            if "PGRST204" in err_msg:
                match = re.search(r"Could not find the '([^']+)' column", err_msg)
                if match:
                    failed_col = match.group(1)
                    if failed_col in payload:
                        print(f"[WARNING] Column '{failed_col}' not found in table '{table_name}'. Removing from payload and retrying.")
                        del payload[failed_col]
                        continue
            return False, e


def _get_user_uuid(username_or_email):
    """Retrieve UUID for a user by email, username, or checking if it's already a UUID (caching via flask session)."""
    if not supabase:
        return None
        
    username_or_email_str = str(username_or_email).strip()
    
    # 1. Check if the string matches UUID format directly
    if len(username_or_email_str) == 36 and username_or_email_str.count('-') == 4:
        return username_or_email_str
        
    # 2. Try Flask session cache first to eliminate duplicate DB lookups
    try:
        from flask import session
        if 'user_id' in session and session.get('username') == username_or_email_str:
            return session['user_id']
        if 'user_id' in session and session.get('email') == username_or_email_str:
            return session['user_id']
    except RuntimeError:
        pass  # Outside request context (e.g. migrate_data.py or test_pipeline.py)
        
    # 3. Check email lookup
    if '@' in username_or_email_str:
        try:
            res = supabase.table('users').select('id').eq('email', username_or_email_str).execute()
            if res.data:
                uuid_val = res.data[0]['id']
                try:
                    from flask import session
                    session['user_id'] = uuid_val
                except RuntimeError:
                    pass
                return uuid_val
        except Exception:
            pass
            
    # 4. Check username lookup
    try:
        res = supabase.table('users').select('id').eq('username', username_or_email_str).execute()
        if res.data:
            uuid_val = res.data[0]['id']
            try:
                from flask import session
                session['user_id'] = uuid_val
            except RuntimeError:
                pass
            return uuid_val
    except Exception:
        pass
        
    return None

# --- User Management ---

def add_user(username, email, password_hash, full_name=None, mobile_number=None, location=None, role=None, organization=None, profile_photo_url=None, provider=None, account_created_date=None, last_login=None):
    """Registers a user profile record in public.users. Auth record must be provisioned beforehand or on registration."""
    if not supabase:
        return False, "Database not configured."
        
    try:
        # Check if username or email already taken in profile table
        existing = supabase.table('users').select('id').or_(f"username.eq.{username},email.eq.{email}").execute()
        if existing.data:
            return False, "Username or email already exists."
    except Exception as e:
        print(f"Error checking existing users: {e}")

    user_uuid = _get_user_uuid(email) or _get_user_uuid(username)
    
    if not user_uuid:
        try:
            # Programmatically provision auth record via admin API
            auth_user = supabase.auth.admin.create_user({
                "email": email,
                "password": password_hash, # Using hashed hex string as password securely
                "email_confirm": True,
                "user_metadata": {
                    "username": username,
                    "full_name": full_name or username.title()
                }
            })
            user_uuid = auth_user.user.id
        except Exception as auth_err:
            return False, f"Auth provisioning failed: {auth_err}"
            
    payload = {
        "id": user_uuid,
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "full_name": full_name or username.title(),
        "mobile_number": mobile_number or "",
        "location": location or "Hyderabad, Telangana, India",
        "bio": "",
        "role": role or 'Threat Analyst',
        "organization": organization or 'Cyber Black Threat Intel Platform',
        "profile_photo_url": profile_photo_url or '',
        "avatar_url": profile_photo_url or '',
        "provider": provider or 'local',
        "created_at": account_created_date or datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "last_login": last_login or datetime.now().isoformat()
    }
    
    success, res = _robust_insert('users', payload)
    if success:
        # Initialize default settings record
        get_settings(username)
        return True, "User registered successfully."
    else:
        return False, f"Profile insertion failed: {res}"

def sync_google_user_profile(user_uuid, email, full_name, avatar_url):
    """Synchronizes Google profile info into the public.users database."""
    if not supabase:
        return False, "Database not configured."
        
    try:
        # Check if profile already exists in public.users
        res = supabase.table('users').select('*').eq('id', user_uuid).execute()
    except Exception as e:
        print(f"Error checking profile in sync_google_user_profile: {e}")
        return False, f"Database check failed: {e}"
    
    payload = {
        "email": email,
        "full_name": full_name,
        "profile_photo_url": avatar_url,
        "avatar_url": avatar_url,
        "provider": "google",
        "last_login": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }
    
    if res.data:
        # Profile exists, update it
        success, update_res = _robust_update('users', payload, user_uuid)
        return success
    else:
        # Profile does not exist, create it!
        # First generate username
        base_username = email.split('@')[0].replace('.', '_').replace('-', '_')
        username = base_username
        counter = 1
        while get_user(username) is not None:
            username = f"{base_username}_{counter}"
            counter += 1
            
        payload["id"] = user_uuid
        payload["username"] = username
        payload["role"] = "Threat Analyst"
        payload["organization"] = "Cyber Black Threat Intel Platform"
        payload["location"] = "Hyderabad, Telangana, India"
        payload["bio"] = ""
        payload["created_at"] = datetime.now().isoformat()
        
        success, insert_res = _robust_insert('users', payload)
        if success:
            get_settings(username)
        return success

def get_user(username):
    """Retrieve user details by username."""
    if not supabase:
        return None
    try:
        res = supabase.table('users').select('*').eq('username', username).execute()
        if res.data:
            user_data = res.data[0]
            if 'password_hash' not in user_data:
                user_data['password_hash'] = ''
            return user_data
    except Exception as e:
        print(f"Error in get_user: {e}")
    return None

def get_user_by_email(email):
    """Retrieve user details by email."""
    if not supabase:
        return None
    try:
        res = supabase.table('users').select('*').eq('email', email).execute()
        if res.data:
            user_data = res.data[0]
            if 'password_hash' not in user_data:
                user_data['password_hash'] = ''
            return user_data
    except Exception as e:
        print(f"Error in get_user_by_email: {e}")
    return None

def update_user(current_username, full_name=None, username=None, email=None, location=None, bio=None, role=None, organization=None):
    """Update user profile record."""
    if not supabase:
        return False, "Database not configured."
        
    user_uuid = _get_user_uuid(current_username)
    if not user_uuid:
        return False, "User not found."
        
    target_username = username.strip() if username else current_username
    if target_username.lower() != current_username.lower():
        existing = supabase.table('users').select('id').eq('username', target_username).execute()
        if existing.data:
            return False, "Username is already taken."
            
    update_data = {}
    if full_name is not None: update_data['full_name'] = full_name.strip()
    if username is not None: update_data['username'] = target_username
    if email is not None: update_data['email'] = email.strip()
    if location is not None: update_data['location'] = location.strip()
    if bio is not None: update_data['bio'] = bio
    if role is not None: update_data['role'] = role.strip()
    if organization is not None: update_data['organization'] = organization.strip()
    update_data['updated_at'] = datetime.now().isoformat()
    
    try:
        supabase.table('users').update(update_data).eq('id', user_uuid).execute()
        
        # Sync email update with auth system if modified
        current_email = get_user(target_username).get('email', '')
        if email and email.strip().lower() != current_email.lower():
            supabase.auth.admin.update_user_by_id(user_uuid, {"email": email.strip()})
            
        return True, "Profile updated successfully."
    except Exception as e:
        print(f"Error in update_user: {e}")
        return False, f"Failed to update profile: {e}"

# --- Investigation History ---

def add_history(username, ip, country, isp, asn, risk_score, classification, threat_summary, recommendations, abuse_score, vt_detections, source='manual', duration_ms=0, sources_used='AbuseIPDB, VirusTotal, WHOIS', actions_taken='Lookup Completed', notes='', severity='Low', tags=''):
    """Log an investigation search to Supabase."""
    if not supabase:
        return None
        
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return None
        
    new_log = {
        'user_id': user_uuid,
        'ip': ip,
        'country': country or 'Unknown',
        'isp': isp or 'Unknown',
        'asn': asn or 'Unknown',
        'risk_score': int(risk_score),
        'classification': classification,
        'threat_summary': threat_summary,
        'recommendations': recommendations,
        'abuse_score': int(abuse_score),
        'vt_detections': int(vt_detections),
        'source': source,
        'duration_ms': int(duration_ms),
        'sources_used': sources_used,
        'actions_taken': actions_taken,
        'notes': notes,
        'severity': severity,
        'tags': tags,
        'created_at': datetime.now().isoformat()
    }
    try:
        res = supabase.table('investigations').insert(new_log).execute()
        if res.data:
            data = res.data[0]
            data['username'] = username
            data['date'] = data['created_at']
            return data
    except Exception as e:
        err_msg = str(e)
        if "duration_ms" in err_msg or "PGRST204" in err_msg or "notes" in err_msg:
            print("[WARNING] V4.0 timeline columns not found in database. Retrying fallback insert.")
            legacy_log = {k: v for k, v in new_log.items() if k not in ['duration_ms', 'sources_used', 'actions_taken', 'notes', 'severity', 'tags']}
            try:
                res = supabase.table('investigations').insert(legacy_log).execute()
                if res.data:
                    data = res.data[0]
                    data['username'] = username
                    data['date'] = data['created_at']
                    return data
            except Exception as e2:
                print(f"Error in fallback add_history: {e2}")
        else:
            print(f"Error in add_history: {e}")
    return None

def get_history(username=None):
    """Retrieve investigation history rows (including V4.0 custom metrics)."""
    if not supabase:
        return []
    try:
        if username:
            user_uuid = _get_user_uuid(username)
            if not user_uuid:
                return []
            try:
                res = supabase.table('investigations').select('id, ip, country, isp, asn, risk_score, classification, abuse_score, vt_detections, source, created_at, duration_ms, sources_used, actions_taken, notes, severity, tags').eq('user_id', user_uuid).order('created_at', desc=True).execute()
            except Exception as e:
                err_msg = str(e)
                if "duration_ms" in err_msg or "PGRST204" in err_msg or "42703" in err_msg:
                    print("[WARNING] V4.0 timeline columns not found in database. Retrying fallback get_history select.")
                    res = supabase.table('investigations').select('id, ip, country, isp, asn, risk_score, classification, abuse_score, vt_detections, source, created_at').eq('user_id', user_uuid).order('created_at', desc=True).execute()
                else:
                    raise e
        else:
            try:
                res = supabase.table('investigations').select('id, ip, country, isp, asn, risk_score, classification, abuse_score, vt_detections, source, created_at, duration_ms, sources_used, actions_taken, notes, severity, tags, users(username)').order('created_at', desc=True).execute()
            except Exception as e:
                err_msg = str(e)
                if "duration_ms" in err_msg or "PGRST204" in err_msg or "42703" in err_msg:
                    print("[WARNING] V4.0 timeline columns not found in database. Retrying fallback get_history select.")
                    res = supabase.table('investigations').select('id, ip, country, isp, asn, risk_score, classification, abuse_score, vt_detections, source, created_at, users(username)').order('created_at', desc=True).execute()
                else:
                    raise e
            
        mapped = []
        for row in res.data:
            row['username'] = row['users']['username'] if row.get('users') else (username or 'Unknown')
            row['date'] = row['created_at']
            row['risk_score'] = str(row['risk_score'])
            row['abuse_score'] = str(row['abuse_score'])
            row['vt_detections'] = str(row['vt_detections'])
            # Safeguards for fallback compatibility if columns are missing in returned dict
            row['duration_ms'] = row.get('duration_ms', 0)
            row['sources_used'] = row.get('sources_used', 'AbuseIPDB, VirusTotal, WHOIS')
            row['actions_taken'] = row.get('actions_taken', 'Lookup Completed')
            row['notes'] = row.get('notes', '')
            row['severity'] = row.get('severity', 'Low')
            row['tags'] = row.get('tags', '')
            mapped.append(row)
        return mapped
    except Exception as e:
        print(f"Error in get_history: {e}")
        return []

def update_investigation_notes(investigation_id, username, notes, severity, tags, actions_taken=None):
    """Update custom analyst notes, severity, and tags on an existing scan log."""
    if not supabase:
        return False
    try:
        payload = {
            'notes': notes,
            'severity': severity,
            'tags': tags
        }
        if actions_taken:
            payload['actions_taken'] = actions_taken
        supabase.table('investigations').update(payload).eq('id', investigation_id).execute()
        return True
    except Exception as e:
        print(f"Error in update_investigation_notes: {e}")
        return False



# --- Watchlist ---

def add_to_watchlist(ip, username, risk_score, classification, reason, status='Active'):
    """Add target IP to watchlist."""
    if not supabase:
        return False, "Database not configured."
        
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False, "User not found."
        
    try:
        existing = supabase.table('watchlists').select('id').eq('user_id', user_uuid).eq('ip', ip).execute()
        if existing.data:
            return False, "IP is already on your watchlist."
            
        new_entry = {
            'user_id': user_uuid,
            'ip': ip,
            'risk_score': int(risk_score),
            'classification': classification,
            'reason': reason or 'Security Analyst Review',
            'status': status,
            'created_at': datetime.now().isoformat()
        }
        supabase.table('watchlists').insert(new_entry).execute()
        return True, "IP added to watchlist."
    except Exception as e:
        print(f"Error in add_to_watchlist: {e}")
        return False, f"Failed to update watchlist: {e}"

def remove_from_watchlist(ip, username):
    """Delete IP from watchlist for a user."""
    if not supabase:
        return False, "Database not configured."
        
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False, "User not found."
        
    try:
        res = supabase.table('watchlists').delete().eq('user_id', user_uuid).eq('ip', ip).execute()
        if res.data:
            return True, "IP removed from watchlist."
        return False, "IP not found in watchlist."
    except Exception as e:
        print(f"Error in remove_from_watchlist: {e}")
        return False, f"Failed to delete from watchlist: {e}"

def get_watchlist(username=None):
    """Retrieve watchlist rows (restricted select columns)."""
    if not supabase:
        return []
    try:
        if username:
            user_uuid = _get_user_uuid(username)
            if not user_uuid:
                return []
            res = supabase.table('watchlists').select('ip, risk_score, classification, reason, status, created_at').eq('user_id', user_uuid).order('created_at', desc=True).execute()
        else:
            res = supabase.table('watchlists').select('ip, risk_score, classification, reason, status, created_at, users(username)').order('created_at', desc=True).execute()
            
        mapped = []
        for row in res.data:
            row['username'] = row['users']['username'] if row.get('users') else (username or 'Unknown')
            row['date_added'] = row['created_at']
            row['risk_score'] = str(row['risk_score'])
            mapped.append(row)
        return mapped
    except Exception as e:
        print(f"Error in get_watchlist: {e}")
        return []

def is_in_watchlist(ip, username):
    """Check if IP is active in user watchlist."""
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        res = supabase.table('watchlists').select('id').eq('user_id', user_uuid).eq('ip', ip).execute()
        return bool(res.data)
    except Exception as e:
        print(f"Error in is_in_watchlist: {e}")
        return False

# --- Malicious IPs Cache ---

def add_malicious_ip(ip, risk_score, classification, reason):
    """Update list of detected malicious IPs."""
    if not supabase:
        return False
    try:
        new_row = {
            'ip': ip,
            'risk_score': int(risk_score),
            'classification': classification,
            'reason': reason,
            'last_detected': datetime.now().isoformat()
        }
        supabase.table('threat_reports').upsert(new_row, on_conflict='ip').execute()
        return True
    except Exception as e:
        print(f"Error in add_malicious_ip: {e}")
        return False

def get_malicious_ips():
    """Retrieve cache of malicious IPs."""
    if not supabase:
        return []
    try:
        res = supabase.table('threat_reports').select('*').order('last_detected', desc=True).execute()
        mapped = []
        for row in res.data:
            row['risk_score'] = str(row['risk_score'])
            mapped.append(row)
        return mapped
    except Exception as e:
        print(f"Error in get_malicious_ips: {e}")
        return []

# --- Application Settings ---

def get_settings(username):
    """Get persisted settings configuration for user (caching via flask session)."""
    if not supabase:
        return {}
        
    # Check Flask session cache first to avoid DB query
    try:
        from flask import session
        if 'settings' in session and session.get('username') == username:
            return session['settings']
    except RuntimeError:
        pass
        
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return {}
    try:
        res = supabase.table('app_settings').select('*').eq('user_id', user_uuid).execute()
        if res.data:
            settings_dict = res.data[0]
            try:
                from flask import session
                session['settings'] = settings_dict
            except RuntimeError:
                pass
            return settings_dict
        else:
            default_settings = {
                "user_id": user_uuid,
                "timezone": "Local",
                "auto_refresh": "5",
                "email_alerts": False,
                "desktop_notifications": False,
                "report_header": "Cyber Black Threat Audit Summary",
                "include_whois": True,
                "export_format": "csv",
                "session_timeout": "4",
                "auto_watchlist_score": 75,
                "mock_mode": False,
                "abuseipdb_key": "",
                "virustotal_key": ""
            }
            supabase.table('app_settings').insert(default_settings).execute()
            try:
                from flask import session
                session['settings'] = default_settings
            except RuntimeError:
                pass
            return default_settings
    except Exception as e:
        print(f"Error in get_settings: {e}")
        return {}

def save_settings(username, settings_dict):
    """Update settings configurations (synchronizing flask session)."""
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        payload = dict(settings_dict)
        payload.pop('user_id', None)
        payload['updated_at'] = datetime.now().isoformat()
        supabase.table('app_settings').update(payload).eq('user_id', user_uuid).execute()
        
        # Sync Flask session cache
        try:
            from flask import session
            payload['user_id'] = user_uuid
            session['settings'] = payload
        except RuntimeError:
            pass
        return True
    except Exception as e:
        print(f"Error in save_settings: {e}")
        return False

# --- User Notifications ---

def get_notifications(username):
    """Get notification alerts queue for user (caching via flask session)."""
    if not supabase:
        return []
        
    # Check Flask session cache first
    try:
        from flask import session
        if 'notifications_cached' in session and session.get('username') == username:
            return session['notifications_cached']
    except RuntimeError:
        pass
        
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return []
    try:
        res = supabase.table('notifications').select('icon, color, title, message, created_at').eq('user_id', user_uuid).order('created_at', desc=True).execute()
        
        # Populate session cache
        try:
            from flask import session
            session['notifications_cached'] = res.data
        except RuntimeError:
            pass
        return res.data
    except Exception as e:
        print(f"Error in get_notifications: {e}")
        return []

def add_notification(username, icon, color, title, message):
    """Enqueue alert notification (synchronizing session cache)."""
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        new_notif = {
            'user_id': user_uuid,
            'icon': icon,
            'color': color,
            'title': title,
            'message': message,
            'created_at': datetime.now().isoformat()
        }
        supabase.table('notifications').insert(new_notif).execute()
        
        # Sync Flask session cache
        try:
            from flask import session
            if 'notifications_cached' not in session:
                session['notifications_cached'] = []
            cached = list(session['notifications_cached'])
            cached.insert(0, {
                'icon': icon,
                'color': color,
                'title': title,
                'message': message,
                'created_at': new_notif['created_at']
            })
            session['notifications_cached'] = cached[:20]
        except RuntimeError:
            pass
        return True
    except Exception as e:
        print(f"Error in add_notification: {e}")
        return False

def clear_notifications(username):
    """Clear all alert records for user (synchronizing session cache)."""
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        supabase.table('notifications').delete().eq('user_id', user_uuid).execute()
        
        # Sync Flask session cache
        try:
            from flask import session
            session['notifications_cached'] = []
        except RuntimeError:
            pass
        return True
    except Exception as e:
        print(f"Error in clear_notifications: {e}")
        return False

def update_investigation_source(username, ip, old_source, new_source):
    """Update investigation log source (replaces legacy CSV batch save)."""
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        supabase.table('investigations').update({'source': new_source}).eq('user_id', user_uuid).eq('ip', ip).eq('source', old_source).execute()
        return True
    except Exception as e:
        print(f"Error in update_investigation_source: {e}")
        return False

# --- Activity Logger ---

def add_activity_log(username, action, details):
    """Log audits to PostgreSQL."""
    # Note: Not active by default in frontend workflow, prepared for security extensions
    if not supabase:
        return False
    user_uuid = _get_user_uuid(username)
    if not user_uuid:
        return False
    try:
        log_entry = {
            'user_id': user_uuid,
            'action': action,
            'details': details,
            'created_at': datetime.now().isoformat()
        }
        # In case activity_logs table was not setup, catch connection error gracefully
        supabase.table('activity_logs').insert(log_entry).execute()
        return True
    except Exception:
        return False

# Verify Supabase connection on module import
if supabase:
    try:
        supabase.table('users').select('id').limit(1).execute()
        print("[+] Supabase connection verified successfully.")
    except Exception as e:
        print(f"[WARNING] Supabase database tables might not be deployed yet: {e}")
else:
    print("[WARNING] Supabase environment variables are missing or incorrect.")
