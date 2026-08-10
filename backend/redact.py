"""
Strip configured secrets out of anything the process emits.

The demo forwards upstream failures verbatim so a user can fix their own
provider config — `detail=str(exc)` for Guard errors, and up to 300 characters
of the provider's response body for LLM errors. That is genuinely useful, but
`base_url` is user-controlled (LM Studio, Ollama, a corporate gateway, a typo),
so the text being forwarded is arbitrary third-party output. A provider that
echoes the Authorization header, or authenticates by query string, puts the key
straight into an error banner and a log line.

The key was already sent to that host, so the host learns nothing new. What this
prevents is the second hop: the key landing in a log file, a log collector, a
screenshot, or a pasted bug report — places with a completely different audience
from the provider the user chose to trust.

The process knows its own secrets, so it can refuse to repeat them. Registration
is a callable rather than a snapshot because these are runtime-mutable globals:
a key set through the UI after startup must be redacted too.
"""
from __future__ import annotations

from typing import Callable

PLACEHOLDER = "«redacted»"

# Below this length a "secret" is more likely a blank/placeholder than a real
# credential, and substring-replacing something short would corrupt unrelated
# text. Real provider keys are far longer.
MIN_SECRET_LEN = 12

_providers: list[Callable[[], list[str]]] = []


def register(provider: Callable[[], list[str]]) -> None:
    """Register a callable returning the currently-configured secret values."""
    _providers.append(provider)


def reset() -> None:
    """Drop all providers — for tests."""
    _providers.clear()


def current_secrets() -> list[str]:
    values: list[str] = []
    for provider in _providers:
        try:
            values.extend(provider() or [])
        except Exception:                      # noqa: BLE001
            # A redactor that raises must never take down the code path it is
            # protecting — failing to log beats crashing a request.
            continue
    # Longest first: if one secret contains another, redact the longer match
    # first so no fragment of it survives.
    return sorted(
        {v for v in values if isinstance(v, str) and len(v.strip()) >= MIN_SECRET_LEN},
        key=len,
        reverse=True,
    )


def scrub(text: str) -> str:
    """Replace every configured secret in `text` with the placeholder."""
    if not text:
        return text
    for secret in current_secrets():
        if secret in text:
            text = text.replace(secret, PLACEHOLDER)
        # Also catch percent-encoded copies, which is how a key looks once it has
        # been through a query string.
        quoted = secret.replace("/", "%2F").replace("+", "%2B").replace("=", "%3D")
        if quoted != secret and quoted in text:
            text = text.replace(quoted, PLACEHOLDER)
    return text


def scrub_obj(obj):
    """Recursively scrub strings inside dicts/lists — for structured details."""
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, dict):
        return {k: scrub_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(scrub_obj(v) for v in obj)
    return obj


class RedactingFilter:
    """
    Logging filter that scrubs the formatted message of every record.

    Installed on the handler rather than applied at each call site: the whole
    point is to cover the log lines nobody remembered to audit, including ones
    added later and ones raised from inside dependencies.
    """

    def filter(self, record) -> bool:                      # logging.Filter protocol
        try:
            if record.args:
                # Render now so the secret cannot re-appear at format time.
                record.msg = scrub(record.getMessage())
                record.args = ()
            elif isinstance(record.msg, str):
                record.msg = scrub(record.msg)
            if record.exc_text:
                record.exc_text = scrub(record.exc_text)
        except Exception:                                  # noqa: BLE001
            pass
        return True
