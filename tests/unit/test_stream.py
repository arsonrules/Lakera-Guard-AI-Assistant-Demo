"""Offline test that the one-shot NDJSON stream sends keep-alive pings during a
gap, so a slow scenario can't make the connection go idle ("network error")."""
import asyncio
import json

import backend.main as main
from backend.main import OneShotRequest, api_oneshot_stream


async def _collect(resp):
    msgs = []
    async for chunk in resp.body_iterator:
        for line in chunk.splitlines():
            if line.strip():
                msgs.append(json.loads(line))
    return msgs


async def test_stream_heartbeat_during_slow_scenario(monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "k")
    monkeypatch.setattr(main, "ONESHOT_STREAM_KEEPALIVE", 0.05)   # tiny so a ping fires fast
    monkeypatch.setattr(main, "_prepare_oneshot_rows",
                        lambda req: ([{"id": "A", "order": 0, "label": "x"}], {"sampled": False}))
    monkeypatch.setattr(main, "_oneshot_summary", lambda results, req, scope: {"ok": True})

    async def slow(*a, **k):
        await asyncio.sleep(0.18)        # longer than the keepalive → forces pings
        return {"id": "A", "order": 0, "label": "x", "outcome": "blocked"}
    monkeypatch.setattr(main, "_run_one_resilient", slow)

    resp = await api_oneshot_stream(OneShotRequest())
    types = [m["type"] for m in await _collect(resp)]

    assert types[0] == "start"          # immediate first byte
    assert "ping" in types              # heartbeat kept the connection alive
    assert types[-1] == "done"          # completed normally
    assert "progress" in types


async def test_stream_reports_error_event(monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "k")
    monkeypatch.setattr(main, "_prepare_oneshot_rows",
                        lambda req: ([{"id": "A", "order": 0}], {"sampled": False}))

    async def boom(*a, **k):
        raise RuntimeError("producer exploded")
    monkeypatch.setattr(main, "_run_one_resilient", boom)

    resp = await api_oneshot_stream(OneShotRequest())
    msgs = await _collect(resp)
    assert msgs[-1]["type"] == "error" and "producer exploded" in msgs[-1]["detail"]
