"""
Concurrency-safe async rate limiter (token bucket) for the outbound request path.

Every network call in the one-shot pipeline — Lakera Guard scans (`lakera.check`)
and target/judge LLM completions (`llm.complete_chat` / `complete_with_tools` /
`test_connection`) — first `await ratelimit.acquire()`. That single chokepoint
caps the *rate* (requests per second) across all concurrent workers, which is a
different guarantee than the concurrency semaphore (how many run at once): the
semaphore bounds in-flight requests, the limiter bounds their start rate.

Why a token bucket (and not a naive "sleep 1/rate between calls"):
  • It is concurrency-safe. A single `asyncio.Lock` serialises token accounting,
    so N parallel workers can never collectively exceed `rate` per second.
  • It holds **no per-waiter state** — waiters just `await asyncio.sleep(...)` and
    re-check. Nothing is appended to a list/dict per queued request, so a large
    backlog of callers cannot leak memory (the classic failure mode of a limiter
    that parks a Future per waiter and forgets to evict it). Combined with the
    bounded worker pool in `main.run_oneshot`, at most `concurrency` coroutines
    are ever parked on `acquire()` at once.

The module-level shared limiter starts UNLIMITED so importing this has zero effect
on the web app and the test suite; the CLI opts in via `configure(rate)`.
"""
from __future__ import annotations

import asyncio
import time

# rate <= 0 means "no throttling" (the default for the library/web app).
UNLIMITED = 0.0

# Token accounting is floating point: refilling by `elapsed * rate` accumulates
# rounding dust, so a bucket that should hold exactly 1.0 token can land on
# 0.9999999999. Without a tolerance the `>= tokens` check would never pass and a
# waiter would spin on ever-shrinking sleeps. This epsilon absorbs that dust.
_EPS = 1e-9


class AsyncRateLimiter:
    """A monotonic-clock token bucket. `rate` tokens are added per second up to a
    `burst` ceiling; each `acquire()` spends one token, waiting if the bucket is
    empty. Safe to share across any number of concurrent asyncio tasks."""

    def __init__(self, rate: float = UNLIMITED, *, burst: float | None = None) -> None:
        self._lock = asyncio.Lock()
        self._configure(rate, burst)

    def _configure(self, rate: float, burst: float | None) -> None:
        self._rate = max(0.0, float(rate))
        # Default the bucket capacity to one second's worth of tokens (min 1), so a
        # brief idle period lets up to `rate` requests fire back-to-back, then the
        # steady state settles to `rate`/sec.
        self._capacity = float(burst) if burst else max(1.0, self._rate)
        self._tokens = self._capacity
        self._updated = time.monotonic()

    def configure(self, rate: float, *, burst: float | None = None) -> None:
        """Change the rate at runtime (the CLI calls this once at startup)."""
        self._configure(rate, burst)

    @property
    def rate(self) -> float:
        return self._rate

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until `tokens` are available, then spend them. No-op when unlimited."""
        if self._rate <= 0:
            return
        while True:
            async with self._lock:
                now = time.monotonic()
                # Refill for the elapsed time, capped at the bucket size.
                self._tokens = min(self._capacity,
                                   self._tokens + (now - self._updated) * self._rate)
                self._updated = now
                if self._tokens >= tokens - _EPS:      # tolerate float refill dust
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self._rate
            # Sleep OUTSIDE the lock so other workers keep accounting fairly; the
            # loop re-checks after waking (tokens may have been taken meanwhile).
            await asyncio.sleep(wait)


# ── Process-wide shared limiter ───────────────────────────────────────────────
# Default UNLIMITED: neither the web app nor the test suite is throttled unless a
# caller (the CLI) explicitly configures a rate.
_shared = AsyncRateLimiter(UNLIMITED)


def configure(rate: float, *, burst: float | None = None) -> None:
    """Set the shared limiter's rate (requests/second). <=0 disables throttling."""
    _shared.configure(rate, burst=burst)


def reset() -> None:
    """Restore the shared limiter to UNLIMITED (e.g. after a CLI run)."""
    _shared.configure(UNLIMITED)


def current_rate() -> float:
    return _shared.rate


async def acquire(tokens: float = 1.0) -> None:
    """Acquire from the shared limiter — the single chokepoint every sender uses."""
    await _shared.acquire(tokens)
