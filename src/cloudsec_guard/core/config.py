import os
from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """
    Secure configuration management using Pydantic.
    Automatically loads variables from the environment.
    """
    # Using SecretStr prevents the key from being accidentally printed in logs
    google_api_key: SecretStr = Field(
    default_factory=lambda: SecretStr(os.getenv("GEMINI_API_KEY", "")),
    description="Google Gemini API Key"
)
    
    # Model configuration
    ai_model_name: str = Field(
        default="gemini-1.5-pro",
        description="The default lightweight and fast Gemini model to use."
    )

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

# Global settings instance
try:
    settings = Settings()
except ValidationError as e:
    print(f"[SECURITY ALERT] Configuration error: {e}")
    settings = None
    
