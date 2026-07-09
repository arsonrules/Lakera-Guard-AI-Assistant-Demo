"""Offline tests for the async token-bucket rate limiter (backend.ratelimit) and
the bounded worker pool (main._run_rows_bounded). A fake monotonic clock + fake
asyncio.sleep make the timing deterministic (no real waiting)."""
import asyncio

import pytest

import backend.main as main
from backend import ratelimit


class _Clock:
    """A controllable monotonic clock. `sleep(d)` advances it and returns at once,
    so token refills happen exactly as if `d` seconds had elapsed — no real wait."""

    def __init__(self):
        self.t = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self):
        return self.t

    async def sleep(self, d):
        self.sleeps.append(d)
        self.t += max(0.0, d)


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(ratelimit.time, "monotonic", c.monotonic)
    monkeypatch.setattr(ratelimit.asyncio, "sleep", c.sleep)
    return c


@pytest.fixture(autouse=True)
def _reset_shared():
    ratelimit.reset()
    yield
    ratelimit.reset()


# ── token bucket ──────────────────────────────────────────────────────────────

async def test_unlimited_never_sleeps(clock):
    lim = ratelimit.AsyncRateLimiter(ratelimit.UNLIMITED)
    for _ in range(50):
        await lim.acquire()
    assert clock.sleeps == []            # rate<=0 is a pure no-op


async def test_burst_then_throttle(clock):
    # rate 8/s, default capacity 8: the first 8 fire free, the 9th must wait 1/8s.
    lim = ratelimit.AsyncRateLimiter(8)
    for _ in range(8):
        await lim.acquire()
    assert clock.sleeps == []            # drained the full bucket, no wait yet
    await lim.acquire()
    assert clock.sleeps == [pytest.approx(0.125)]   # one token @ 8/s = 0.125s


async def test_steady_state_rate(clock):
    # From an empty bucket, each further token costs exactly 1/rate seconds.
    lim = ratelimit.AsyncRateLimiter(4, burst=1)
    await lim.acquire()                  # spends the single starting token, no wait
    for _ in range(5):
        await lim.acquire()
    assert clock.sleeps == [pytest.approx(0.25)] * 5   # 4/s → 0.25s apart


async def test_configure_and_current_rate(clock):
    lim = ratelimit.AsyncRateLimiter(ratelimit.UNLIMITED)
    assert lim.rate == 0
    lim.configure(10)
    assert lim.rate == 10


async def test_concurrent_workers_share_one_bucket(clock):
    # 10 tasks race on a shared 5/s limiter (capacity 5). Total spend beyond the
    # initial burst must be paced by the bucket — never faster than 5/s.
    lim = ratelimit.AsyncRateLimiter(5, burst=5)

    async def worker():
        await lim.acquire()

    await asyncio.gather(*[worker() for _ in range(10)])
    # 5 free from the burst; the other 5 each waited a positive amount.
    assert len(clock.sleeps) == 5
    assert all(s > 0 for s in clock.sleeps)


# ── shared module-level limiter ───────────────────────────────────────────────

async def test_shared_configure_reset(clock):
    assert ratelimit.current_rate() == 0
    ratelimit.configure(8)
    assert ratelimit.current_rate() == 8
    await ratelimit.acquire()            # uses the shared bucket
    ratelimit.reset()
    assert ratelimit.current_rate() == 0


# ── bounded worker pool (memory safety for large batches) ─────────────────────

async def test_bounded_pool_runs_all_and_caps_concurrency():
    rows = [{"i": i} for i in range(50)]
    inflight = 0
    peak = 0

    async def run_row(r):
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0)           # yield so other workers can interleave
        inflight -= 1
        return r["i"]

    out = await main._run_rows_bounded(rows, 4, run_row)
    assert sorted(out) == list(range(50))     # every row ran exactly once
    assert peak <= 4                          # never more than the worker count in flight


async def test_bounded_pool_handles_fewer_rows_than_workers():
    rows = [{"i": 0}, {"i": 1}]

    async def run_row(r):
        return r["i"]

    out = await main._run_rows_bounded(rows, 8, run_row)
    assert sorted(out) == [0, 1]              # pool shrinks to len(rows); no idle-task error


async def test_bounded_pool_empty_rows():
    async def run_row(r):                     # pragma: no cover - never called
        raise AssertionError("should not run")

    assert await main._run_rows_bounded([], 4, run_row) == []
