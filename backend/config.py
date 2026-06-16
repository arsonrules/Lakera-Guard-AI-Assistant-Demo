import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict

# .env lives at the project root. Used both to seed startup config and as the
# target for the UI's "Save to .env" so settings persist across restarts.
ENV_PATH = pathlib.Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    # Optional so the app boots with NO .env — keys are then set via the UI.
    lakera_guard_api_key: str = ""

    # ── LLM provider (OpenAI-compatible Chat Completions) ─────────────────────
    # `llm_provider` selects a preset (openrouter | lmstudio | ollama | omlx | custom).
    # Any field left blank falls back to the preset's default at runtime.
    llm_provider: str = "openrouter"
    llm_base_url: str = ""   # blank → use the preset's base URL
    llm_api_key: str = ""    # blank → fall back to openrouter_api_key (back-compat)
    llm_model: str = ""      # blank → use openrouter_model / preset default

    # Back-compat with the original OpenRouter-only configuration.
    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-3-opus"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
