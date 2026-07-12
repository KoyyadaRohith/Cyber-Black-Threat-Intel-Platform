import os
from datetime import datetime
from services.db_operations import supabase

def get_cached_analysis(investigation_id):
    """Retrieve AI analysis for an investigation target from Supabase."""
    if not supabase:
        return None
    try:
        res = supabase.table('ai_analysis').select('*').eq('investigation_id', investigation_id).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        print(f"[AI CACHE WARNING] Failed to read from ai_analysis: {e}")
    return None

def cache_analysis(investigation_id, user_id, provider, model, analysis_dict, processing_time_ms):
    """Save generated AI analysis metrics into public.ai_analysis table."""
    if not supabase:
        return None
    payload = {
        'investigation_id': investigation_id,
        'user_id': user_id,
        'provider': provider,
        'model': model,
        'summary': analysis_dict.get('summary', ''),
        'assessment': analysis_dict.get('assessment', ''),
        'findings': analysis_dict.get('findings', ''),
        'recommendation': analysis_dict.get('recommendation', ''),
        'ioc_explanation': analysis_dict.get('ioc_explanation', ''),
        'next_steps': analysis_dict.get('next_steps', ''),
        'confidence_score': int(analysis_dict.get('confidence_score', 85)),
        'processing_time_ms': int(processing_time_ms),
        'cached': True,
        'created_at': datetime.now().isoformat()
    }
    try:
        res = supabase.table('ai_analysis').insert(payload).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        print(f"[AI CACHE WARNING] Failed to insert cache row: {e}")
    return None
