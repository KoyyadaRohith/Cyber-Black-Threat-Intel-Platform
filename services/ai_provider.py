import os
import json
import requests
from config import Config

class AIProvider:
    def generate(self, system_prompt, user_prompt, temperature=0.2):
        raise NotImplementedError

class GeminiProvider(AIProvider):
    def __init__(self, api_key=None, model="gemini-1.5-flash"):
        self.api_key = api_key or Config.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
        self.model = model or "gemini-1.5-flash"

    def generate(self, system_prompt, user_prompt, temperature=0.2):
        if not self.api_key:
            print("[AI PROVIDER] Gemini key not found. Query skipped.")
            return None
            
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        
        # Format payloads according to official Gemini guidelines
        payload = {
            "contents": [
                {
                    "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]
                }
            ],
            "generationConfig": {
                "temperature": float(temperature)
            }
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=12)
            if response.status_code == 200:
                res_json = response.json()
                candidates = res_json.get("candidates", [])
                if candidates:
                    content = candidates[0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        return parts[0].get("text", "").strip()
            print(f"[AI PROVIDER ERROR] Gemini responded with status {response.status_code}: {response.text}")
        except Exception as e:
            print(f"[AI PROVIDER ERROR] Gemini API POST request failed: {e}")
        return None

class OpenAIProvider(AIProvider):
    def __init__(self, api_key=None, model="gpt-4o-mini"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or "gpt-4o-mini"

    def generate(self, system_prompt, user_prompt, temperature=0.2):
        if not self.api_key:
            return None
        url = "https://api.openai.com/v1/chat/completures"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": float(temperature)
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=12)
            if response.status_code == 200:
                return response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        except Exception as e:
            print(f"[AI PROVIDER ERROR] OpenAI failed: {e}")
        return None

class ClaudeProvider(AIProvider):
    def __init__(self, api_key=None, model="claude-3-5-sonnet"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model or "claude-3-5-sonnet"

    def generate(self, system_prompt, user_prompt, temperature=0.2):
        # Stubbed Claude implementation for future expansion
        return None

class LocalAIProvider(AIProvider):
    def __init__(self, endpoint="http://localhost:11434/api/generate", model="llama3"):
        self.endpoint = endpoint
        self.model = model

    def generate(self, system_prompt, user_prompt, temperature=0.2):
        # Stubbed Ollama / Local AI model generation
        return None
