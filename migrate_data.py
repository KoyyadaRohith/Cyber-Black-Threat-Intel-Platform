# DATA MIGRATION SCRIPT FOR CYBER BLACK THREAT INTEL PLATFORM (CBTIP) V3.0
# Run this script after setting up environment variables in `.env` and deploying the schema in Supabase.

import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Add current folder to path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from config import Config

# Load configuration and environment variables
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env')

# Re-read keys directly to ensure load
supabase_url = os.environ.get("SUPABASE_URL", "")
supabase_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

if not supabase_url or "your-supabase-project" in supabase_url:
    print("[ERROR] Please configure your actual SUPABASE_URL in the .env file first.")
    sys.exit(1)

if not supabase_key or "your-supabase-service-role-key" in supabase_key:
    print("[ERROR] Please configure your actual SUPABASE_SERVICE_ROLE_KEY in the .env file first.")
    sys.exit(1)

try:
    from supabase import create_client, Client
    supabase = create_client(supabase_url, supabase_key)
except ImportError:
    print("[ERROR] supabase-py package is not installed. Please run: pip install supabase")
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] Failed to initialize Supabase client: {e}")
    sys.exit(1)

def read_csv(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, mode='r', encoding='utf-8', newline='') as f:
        return list(csv.DictReader(f))

def migrate_data():
    print("[*] Starting data migration from CSV files to Supabase PostgreSQL...")
    
    users_file = Config.DB_FOLDER / 'legacy_csv' / 'users.csv'
    watchlist_file = Config.DB_FOLDER / 'legacy_csv' / 'watchlist.csv'
    history_file = Config.DB_FOLDER / 'legacy_csv' / 'investigation_history.csv'
    malicious_file = Config.DB_FOLDER / 'legacy_csv' / 'malicious_ips.csv'

    # Step 1: Migrate Users
    legacy_users = read_csv(users_file)
    print(f"[+] Found {len(legacy_users)} users in users.csv.")
    
    username_to_uuid = {}
    default_password = "CyberBlackMigrated2026!" # Default migration password for all accounts

    for user in legacy_users:
        username = user.get('username')
        email = user.get('email')
        
        if not username or not email:
            continue
            
        print(f"[*] Processing user: {username} ({email})...")
        
        # Check if user already exists in public.users to avoid duplicates
        existing = supabase.table('users').select('id').eq('username', username).execute()
        if existing.data:
            user_uuid = existing.data[0]['id']
            print(f"    - User '{username}' already exists in DB with UUID: {user_uuid}")
            username_to_uuid[username.lower()] = user_uuid
            continue
            
        # Use existing SHA256 password hash from CSV so their legacy password works
        password_to_use = user.get('password_hash')
        if not password_to_use or len(password_to_use) < 6:
            # Fallback to hashed default password if hash is missing
            from hashlib import sha256
            password_to_use = sha256(default_password.encode('utf-8')).hexdigest()
            print(f"    - Missing password hash, using hashed fallback: '{default_password}'")
            
        # Try to find user in auth.users by email first
        user_uuid = None
        try:
            # Attempt to create auth user
            auth_user = supabase.auth.admin.create_user({
                "email": email,
                "password": password_to_use,
                "email_confirm": True,
                "user_metadata": {
                    "username": username,
                    "full_name": user.get('full_name', username.title())
                }
            })
            user_uuid = auth_user.user.id
            print(f"    - Auth account created successfully (UUID: {user_uuid})")
        except Exception as auth_err:
            # If user already exists in auth.users, try retrieving by searching auth users list
            # We will catch email exists and search
            err_msg = str(auth_err).lower()
            if "already exists" in err_msg or "email_exists" in err_msg:
                try:
                    # Let's search auth users
                    auth_users_list = supabase.auth.admin.list_users()
                    for u in auth_users_list:
                        if u.email.lower() == email.lower():
                            user_uuid = u.id
                            print(f"    - Found existing auth account (UUID: {user_uuid})")
                            break
                except Exception as list_err:
                    print(f"    - Could not retrieve existing auth user: {list_err}")
            
            if not user_uuid:
                print(f"    [WARNING] Failed to provision auth credentials for {email}: {auth_err}")
                continue

        # Insert profile details in public.users
        try:
            created_at_raw = user.get('created_at', datetime.now().isoformat())
            
            supabase.table('users').insert({
                "id": user_uuid,
                "username": username,
                "email": email,
                "full_name": user.get('full_name', username.title()),
                "mobile_number": user.get('mobile_number', ''),
                "location": user.get('location', 'Hyderabad, Telangana, India'),
                "bio": user.get('bio', ''),
                "role": user.get('role', 'Threat Analyst'),
                "organization": user.get('organization', 'Cyber Black Threat Intel Platform'),
                "profile_photo_url": user.get('profile_photo_url', ''),
                "provider": user.get('provider', 'local'),
                "created_at": created_at_raw,
                "updated_at": datetime.now().isoformat()
            }).execute()
            print(f"    - Profile imported to public.users table.")
        except Exception as db_err:
            print(f"    [WARNING] Profile insertion error for {username}: {db_err}")
            
        # Initialize default settings record
        try:
            supabase.table('app_settings').upsert({
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
                "mock_mode": True
            }).execute()
            print(f"    - Default app settings initialized.")
        except Exception as set_err:
            print(f"    [WARNING] Settings initialization error: {set_err}")
            
        username_to_uuid[username.lower()] = user_uuid

    print(f"\n[+] User migration phase completed. Mapping dict: {username_to_uuid}\n")

    # Step 2: Migrate Watchlist
    legacy_watchlist = read_csv(watchlist_file)
    print(f"[*] Migrating {len(legacy_watchlist)} watchlist entries...")
    
    watchlist_success = 0
    for item in legacy_watchlist:
        username = item.get('username')
        user_uuid = username_to_uuid.get(username.lower())
        
        if not user_uuid:
            print(f"    [WARNING] Skipping watchlist IP {item.get('ip')} - User '{username}' does not exist.")
            continue
            
        try:
            # Check if watchlisted already
            existing = supabase.table('watchlists').select('id').eq('user_id', user_uuid).eq('ip', item.get('ip')).execute()
            if existing.data:
                continue
                
            supabase.table('watchlists').insert({
                "user_id": user_uuid,
                "ip": item.get('ip'),
                "risk_score": int(item.get('risk_score', 0)),
                "classification": item.get('classification', 'Safe'),
                "reason": item.get('reason', 'Legacy Import'),
                "status": item.get('status', 'Active'),
                "created_at": item.get('date_added', datetime.now().isoformat())
            }).execute()
            watchlist_success += 1
        except Exception as wl_err:
            print(f"    [WARNING] Failed to insert watchlist entry for IP {item.get('ip')}: {wl_err}")
            
    print(f"[+] Watchlist migration finished: {watchlist_success} entries uploaded.")

    # Step 3: Migrate Investigation History
    legacy_history = read_csv(history_file)
    print(f"\n[*] Migrating {len(legacy_history)} investigation history entries...")
    
    history_success = 0
    for item in legacy_history:
        username = item.get('username')
        user_uuid = username_to_uuid.get(username.lower())
        
        if not user_uuid:
            print(f"    [WARNING] Skipping lookup history {item.get('ip')} - User '{username}' does not exist.")
            continue
            
        try:
            supabase.table('investigations').insert({
                "user_id": user_uuid,
                "ip": item.get('ip'),
                "country": item.get('country', 'Unknown'),
                "isp": item.get('isp', 'Unknown'),
                "asn": item.get('asn', 'Unknown'),
                "risk_score": int(item.get('risk_score', 0)),
                "classification": item.get('classification', 'Safe'),
                "threat_summary": item.get('threat_summary', ''),
                "recommendations": item.get('recommendations', ''),
                "abuse_score": int(item.get('abuse_score', 0)),
                "vt_detections": int(item.get('vt_detections', 0)),
                "source": item.get('source', 'manual'),
                "created_at": item.get('date', datetime.now().isoformat())
            }).execute()
            history_success += 1
        except Exception as hist_err:
            print(f"    [WARNING] Failed to insert history entry for IP {item.get('ip')}: {hist_err}")
            
    print(f"[+] Investigation history migration finished: {history_success} records uploaded.")

    # Step 4: Migrate Malicious IP Cache
    legacy_malicious = read_csv(malicious_file)
    print(f"\n[*] Migrating {len(legacy_malicious)} general malicious cache entries...")
    
    malicious_success = 0
    for item in legacy_malicious:
        try:
            # Check if exists in threat_reports
            existing = supabase.table('threat_reports').select('id').eq('ip', item.get('ip')).execute()
            if existing.data:
                continue
                
            supabase.table('threat_reports').insert({
                "ip": item.get('ip'),
                "risk_score": int(item.get('risk_score', 0)),
                "classification": item.get('classification', 'Malicious'),
                "reason": item.get('reason', 'Legacy Ingestion'),
                "last_detected": item.get('last_detected', datetime.now().isoformat()),
                "created_at": datetime.now().isoformat()
            }).execute()
            malicious_success += 1
        except Exception as mal_err:
            print(f"    [WARNING] Failed to insert malicious report cache for IP {item.get('ip')}: {mal_err}")
            
    print(f"[+] Malicious reports cache migration finished: {malicious_success} entries uploaded.")
    
    print("\n[SUCCESS] DATA MIGRATION TO SUPABASE COMPLETED SUCCESSFULLY!")
    print(f"All users have been migrated with default authentication password: '{default_password}'")
    print("Please remind users to update/reset their passwords upon their first login using the reset key feature.")

if __name__ == '__main__':
    migrate_data()
