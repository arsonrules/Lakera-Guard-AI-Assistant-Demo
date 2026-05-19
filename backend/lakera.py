import time
import httpx

LAKERA_ENDPOINT = "https://api.lakera.ai/v2/guard"


async def check(text: str, api_key: str) -> dict:
    """Run Lakera Guard v2 on a text string. Returns response dict + latency_ms."""
    start = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            LAKERA_ENDPOINT,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "messages": [{"role": "user", "content": text}],
                "breakdown": True,
            },
            timeout=10.0,
        )
        resp.raise_for_status()
    data = resp.json()
    data["latency_ms"] = int((time.monotonic() - start) * 1000)
    return data


def is_flagged(result: dict) -> bool:
    return result.get("flagged", False)


def flagged_categories(result: dict) -> list[str]:
    """Return detector_type strings for every detector that fired."""
    return [
        item["detector_type"]
        for item in result.get("breakdown", [])
        if item.get("detected")
    ]
