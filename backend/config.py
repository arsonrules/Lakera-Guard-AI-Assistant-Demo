import os
import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict

# .env lives at the project root. Used both to seed startup config and as the
# target for the UI's "Save to .env" so settings persist across restarts.
#
# ENV_FILE overrides the location. Docker Compose sets it to a path inside a
# mounted *directory* — bind-mounting a single file requires that file to already
# exist on the host, or Docker silently creates a directory in its place.
ENV_PATH = pathlib.Path(
    os.environ.get("ENV_FILE") or pathlib.Path(__file__).resolve().parent.parent / ".env"
)


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

    # ── Operations ────────────────────────────────────────────────────────────
    # Root log level (DEBUG | INFO | WARNING | ERROR).
    log_level: str = "INFO"
    # Emit one JSON object per log line — set this in containers so logs are
    # machine-parseable. Blank/false keeps the human-readable console format.
    log_json: bool = False
    # This app deliberately handles adversarial prompts and PII fixtures, so
    # prompt/response bodies are NEVER logged unless this is explicitly enabled.
    log_prompts: bool = False

    # ── Access control (optional) ─────────────────────────────────────────────
    # When set, every /api/* request must present this token (Authorization:
    # Bearer <token>, or the X-Demo-Token header). Blank = open, which is safe
    # only on loopback. See README "Deployment & Security Boundary".
    demo_access_token: str = ""
    # Set to true ONLY if you intentionally expose the demo beyond loopback
    # without a token. Without it, binding to a public interface refuses to boot.
    allow_insecure_bind: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
