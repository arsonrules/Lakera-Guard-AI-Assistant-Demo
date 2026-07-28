FROM python:3.12-slim

WORKDIR /app

# Install from the hash-pinned lock so an image built today and one built in six
# months contain byte-identical dependencies. Regenerate with:
#   uv pip compile requirements.txt --python-version 3.12 --generate-hashes -o requirements.lock
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

# Copy only what the service needs at runtime (keeps tests/, datasets/, reports/
# and docs out of the image). .dockerignore covers the rest.
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY tests/fixtures/ ./tests/fixtures/
COPY suite.yaml ./

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness for `docker ps` / orchestrators. Uses stdlib urllib so the image needs
# no extra tooling (no curl in python:slim).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else sys.exit(1)"

# NOTE: single worker is REQUIRED. Runtime config (LLM/Guard keys, doc mode,
# imported datasets) lives in module-level state, so a second worker would get
# its own copy and serve inconsistent config. Scale by running separate
# instances, not by adding --workers.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
