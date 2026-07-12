-- SQL SCHEMA FOR CYBER BLACK THREAT INTEL PLATFORM (CBTIP) V3.0
-- Copy and run this script in the Supabase SQL Editor (https://supabase.com -> Project -> SQL Editor)

-- 1. Users Table (References built-in auth.users)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) DEFAULT '',
    full_name VARCHAR(150),
    mobile_number VARCHAR(20),
    location VARCHAR(255) DEFAULT 'Hyderabad, Telangana, India',
    bio TEXT,
    role VARCHAR(100) DEFAULT 'Threat Analyst',
    organization VARCHAR(255) DEFAULT 'Cyber Black Threat Intel Platform',
    profile_photo_url TEXT,
    provider VARCHAR(50) DEFAULT 'local',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON public.users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);

-- Enable RLS for Users Table
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read access to profiles" 
ON public.users FOR SELECT 
USING (true);

CREATE POLICY "Allow users to update their own profile" 
ON public.users FOR UPDATE 
USING (auth.uid() = id);

CREATE POLICY "Allow system insertions during signup" 
ON public.users FOR INSERT 
WITH CHECK (true);

-- 2. Investigations Table
CREATE TABLE IF NOT EXISTS public.investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    ip VARCHAR(50) NOT NULL,
    country VARCHAR(100),
    isp VARCHAR(150),
    asn VARCHAR(50),
    risk_score INTEGER NOT NULL,
    classification VARCHAR(50) NOT NULL,
    threat_summary TEXT,
    recommendations TEXT,
    abuse_score INTEGER DEFAULT 0,
    vt_detections INTEGER DEFAULT 0,
    source VARCHAR(255) DEFAULT 'manual',
    duration_ms INTEGER DEFAULT 0,
    sources_used VARCHAR(255) DEFAULT 'AbuseIPDB, VirusTotal, WHOIS',
    actions_taken TEXT DEFAULT 'Lookup Completed',
    notes TEXT DEFAULT '',
    severity VARCHAR(50) DEFAULT 'Low',
    tags VARCHAR(255) DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_investigations_user_id ON public.investigations(user_id);
CREATE INDEX IF NOT EXISTS idx_investigations_ip ON public.investigations(ip);
CREATE INDEX IF NOT EXISTS idx_investigations_asn ON public.investigations(asn);
CREATE INDEX IF NOT EXISTS idx_investigations_country ON public.investigations(country);
CREATE INDEX IF NOT EXISTS idx_investigations_classification ON public.investigations(classification);

-- Enable RLS for Investigations
ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow users to view their own lookup history" 
ON public.investigations FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Allow users to log their own investigations" 
ON public.investigations FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- 3. Watchlists Table
CREATE TABLE IF NOT EXISTS public.watchlists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    ip VARCHAR(50) NOT NULL,
    risk_score INTEGER NOT NULL,
    classification VARCHAR(50) NOT NULL,
    reason TEXT,
    status VARCHAR(50) DEFAULT 'Active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    UNIQUE(user_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_watchlists_user_ip ON public.watchlists(user_id, ip);

-- Enable RLS for Watchlists
ALTER TABLE public.watchlists ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow users to view their own watchlist" 
ON public.watchlists FOR SELECT 
USING (auth.uid() = user_id);

CREATE POLICY "Allow users to manage their own watchlist" 
ON public.watchlists FOR ALL 
USING (auth.uid() = user_id);

-- 4. Threat Reports (Detected Malicious IP Cache)
CREATE TABLE IF NOT EXISTS public.threat_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip VARCHAR(50) UNIQUE NOT NULL,
    risk_score INTEGER NOT NULL,
    classification VARCHAR(50) NOT NULL,
    reason TEXT,
    last_detected TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_reports_ip ON public.threat_reports(ip);

-- Enable RLS for Threat Reports (Global Cache)
ALTER TABLE public.threat_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow authenticated read to global threat reports cache" 
ON public.threat_reports FOR SELECT 
USING (auth.role() = 'authenticated');

CREATE POLICY "Allow service insertions to global threat reports cache" 
ON public.threat_reports FOR ALL 
USING (true);

-- 5. Application Settings Table
CREATE TABLE IF NOT EXISTS public.app_settings (
    user_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    timezone VARCHAR(50) DEFAULT 'Local',
    auto_refresh VARCHAR(50) DEFAULT '5',
    email_alerts BOOLEAN DEFAULT FALSE,
    desktop_notifications BOOLEAN DEFAULT FALSE,
    report_header VARCHAR(255) DEFAULT 'Cyber Black Threat Audit Summary',
    include_whois BOOLEAN DEFAULT TRUE,
    export_format VARCHAR(50) DEFAULT 'csv',
    session_timeout VARCHAR(50) DEFAULT '4',
    auto_watchlist_score INTEGER DEFAULT 75,
    mock_mode BOOLEAN DEFAULT FALSE,
    abuseipdb_key TEXT DEFAULT '',
    virustotal_key TEXT DEFAULT '',
    ai_enabled BOOLEAN DEFAULT TRUE,
    ai_provider VARCHAR(50) DEFAULT 'Gemini',
    ai_model VARCHAR(100) DEFAULT 'gemini-1.5-flash',
    ai_temperature NUMERIC DEFAULT 0.2,
    ai_cache_duration VARCHAR(50) DEFAULT '24h',
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS for App Settings
ALTER TABLE public.app_settings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow users to manage their own app settings" 
ON public.app_settings FOR ALL 
USING (auth.uid() = user_id);

-- 6. Notifications Table
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    icon VARCHAR(100) NOT NULL,
    color VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON public.notifications(user_id);

-- Enable RLS for Notifications
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow users to manage their own notifications feed" 
ON public.notifications FOR ALL 
USING (auth.uid() = user_id);

-- 7. AI Analysis Table
CREATE TABLE IF NOT EXISTS public.ai_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL REFERENCES public.investigations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    provider VARCHAR(50) DEFAULT 'Gemini',
    model VARCHAR(100) DEFAULT 'gemini-1.5-flash',
    summary TEXT,
    assessment TEXT,
    findings TEXT,
    recommendation TEXT,
    ioc_explanation TEXT,
    next_steps TEXT,
    confidence_score INTEGER DEFAULT 85,
    processing_time_ms INTEGER DEFAULT 0,
    cached BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS for AI Analysis
ALTER TABLE public.ai_analysis ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow users to manage their own AI analysis logs" 
ON public.ai_analysis FOR ALL 
USING (auth.uid() = user_id);

CREATE INDEX IF NOT EXISTS idx_ai_analysis_investigation ON public.ai_analysis(investigation_id);

-- Descending sorting indexes for timeline ordering
CREATE INDEX IF NOT EXISTS idx_investigations_created_at_desc ON public.investigations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_watchlists_created_at_desc ON public.watchlists (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at_desc ON public.notifications (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_reports_last_detected_desc ON public.threat_reports (last_detected DESC);

-- V5.0 Migration: Add missing columns to ai_analysis (safe to run on existing tables)
ALTER TABLE public.ai_analysis ADD COLUMN IF NOT EXISTS assessment TEXT;
ALTER TABLE public.ai_analysis ADD COLUMN IF NOT EXISTS findings TEXT;


