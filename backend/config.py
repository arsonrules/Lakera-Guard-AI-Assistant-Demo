import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict

# .env lives at the project root. Used both to seed startup config and as the
# target for the UI's "Save to .env" so settings persist across restarts.
ENV_PATH = pathlib.Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    # Optional so the app boots with NO .env — keys are then set via the UI.
    lakera_guard_api_key: str = ""
    # Optional Lakera project id — selects that project's Guard policy when set.
    lakera_project_id: str = ""
    # Regional Guard endpoint. Blank → the Community default (api.lakera.ai).
    # Accepts a region host (e.g. https://eu-west-1.api.lakera.ai) or full URL.
    lakera_endpoint: str = ""

    # ── LLM provider (OpenAI-compatible Chat Completions) ─────────────────────
    # `llm_provider` selects a preset (openrouter | lmstudio | ollama | omlx | custom).
    # Any field left blank falls back to the preset's default at runtime.
    llm_provider: str = "openrouter"
    llm_base_url: str = ""   # blank → use the preset's base URL
    llm_api_key: str = ""    # blank → fall back to openrouter_api_key (back-compat)
    llm_model: str = ""      # blank → use openrouter_model / preset default

    # ── Independent LLM-as-judge provider (optional) ──────────────────────────
    # When set, the one-shot judge uses THIS provider/model instead of the target
    # model, so a weak local target isn't grading its own output. All blank → the
    # judge falls back to the target llm_* config above.
    judge_provider: str = ""
    judge_base_url: str = ""
    judge_api_key: str = ""
    judge_model: str = ""

    # Back-compat with the original OpenRouter-only configuration.
    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-3-opus"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
