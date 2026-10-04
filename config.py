import tempfile
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env', override=True)

# Detect if running on Vercel / serverless environment
IS_VERCEL = (
    os.getenv("VERCEL") is not None
    or os.getenv("VERCEL_ENV") is not None
    or os.getenv("NOW_REGION") is not None
    or bool(os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
)

# Use writable storage on Vercel
if IS_VERCEL:
    STORAGE_DIR = Path(tempfile.gettempdir()) / "cbtip"
else:
    STORAGE_DIR = BASE_DIR

class Config:
    BASE_DIR = BASE_DIR
    STORAGE_DIR = STORAGE_DIR
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-black-threat-intelligence-secret-key-1234')
    
    # Upload Directories
    UPLOAD_FOLDER = STORAGE_DIR / 'uploads'
    UPLOAD_CSV = UPLOAD_FOLDER / 'csv'
    UPLOAD_TXT = UPLOAD_FOLDER / 'txt'
    UPLOAD_LOGS = UPLOAD_FOLDER / 'logs'
    UPLOAD_AVATARS = UPLOAD_FOLDER / 'avatars'
    
    # Reports Directories
    # Use writable temporary storage on Vercel.
    REPORTS_FOLDER = STORAGE_DIR / 'reports'
    REPORTS_PDF = REPORTS_FOLDER / 'pdf'
    REPORTS_CSV = REPORTS_FOLDER / 'csv'
    REPORTS_TXT = REPORTS_FOLDER / 'txt'

    # Exports Directories
    # Use writable temporary storage on Vercel.
    EXPORTS_FOLDER = STORAGE_DIR / 'exports'
    GENERATED_REPORTS = EXPORTS_FOLDER / 'generated_reports'
    DOWNLOADED_FILES = EXPORTS_FOLDER / 'downloaded_files'

    # Database / runtime cache path
    # Use writable temporary storage on Vercel.
    DB_FOLDER = STORAGE_DIR / 'database'
    
    # API credentials
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    # AI Intelligence Layer - V5.0
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')

    # Supabase credentials
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')
    SUPABASE_SERVICE_ROLE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')

    
    # Server configuration
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'

    @classmethod
    def init_folders(cls):
        """Create necessary project directories if they don't exist."""
        folders = [
            cls.UPLOAD_CSV, cls.UPLOAD_TXT, cls.UPLOAD_LOGS, cls.UPLOAD_AVATARS,
            cls.REPORTS_PDF, cls.REPORTS_CSV, cls.REPORTS_TXT,
            cls.GENERATED_REPORTS, cls.DOWNLOADED_FILES,
            cls.DB_FOLDER
        ]

        for folder in folders:
            try:
                folder.mkdir(parents=True, exist_ok=True)
            except OSError as error:
                print(f"[WARNING] Could not create runtime folder: {folder}: {error}")
