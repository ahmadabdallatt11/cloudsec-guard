from typing import Any, Dict, List, Optional
import google.generativeai as genai

from cloudsec_guard.core.config import settings

class GeminiRemediationAgent:
    """
    AI Agent with smart filtering to explicitly bypass deprecated 2.5-flash 
    and pick the active flash models available on the user's API key.
    """
    def __init__(self):
        api_key = settings.google_api_key.get_secret_value()
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set. Cannot initialize AI.")
        
        genai.configure(api_key=api_key)

    def _get_best_model(self) -> str:
        """
        Dynamically queries Google's API, skips deprecated 2.5-flash, 
        and prioritizes active high-performance flash models.
        """
        try:
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    name = m.name.replace("models/", "")
                    
                    # Explicitly skip the deprecated 2.5-flash that causes 404
                    if "2.5-flash" in name:
                        continue
                    
                    # Prioritize top-tier active flash models from your diagnostic list
                    if "3.7-flash" in name or "3.6-flash" in name or "3.5-flash" in name or "flash-latest" in name:
                        return name
            
            # Fallback to the first available model that is not 2.5-flash
            for m in genai.list_models():
                if 'generateContent' in m.supported_generation_methods:
                    name = m.name.replace("models/", "")
                    if "2.5-flash" not in name:
                        return name
                        
        except Exception as e:
            print(f"[AI WARNING] Could not list models: {e}")
            
        return "gemini-3.7-flash"

    def generate_fix(self, file_content: str, file_type: str, findings: List[Dict[str, Any]]) -> Optional[str]:
        if not findings:
            return "No vulnerabilities found. Code is secure."

        model_name = self._get_best_model()

        prompt = f"""
SYSTEM INSTRUCTION: You are a strict Senior DevSecOps Engineer and security auditor. Provide only factual fixes.

I have a {file_type.upper()} file with the following confirmed security vulnerabilities detected by a static scanner:

FINDINGS:
{findings}

ORIGINAL FILE CONTENT:TASK:
1. Briefly explain the impact of these vulnerabilities in 2-3 sentences.
2. Provide the FULL, corrected {file_type.upper()} file content.
3. You MUST output the corrected code inside a Markdown code block.
4. Do not introduce new features; ONLY fix the reported vulnerabilities.
"""
        try:
            model = genai.GenerativeModel(model_name=model_name)
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=0.2)
            )
            return response.text
            
        except Exception as e:
            print(f"\n[AI ERROR] Failed with model '{model_name}': {e}")
            return None