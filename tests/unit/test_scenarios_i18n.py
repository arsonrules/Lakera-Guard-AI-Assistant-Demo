"""Offline tests for localized scenario prompts served to the live chat."""
from backend import scenarios


def _by_id(cats):
    return {s["id"]: s for c in cats for s in c["scenarios"]}


def test_english_or_unknown_returns_source_unchanged():
    assert scenarios.localized_categories(None) is scenarios.CATEGORIES
    assert scenarios.localized_categories("en") is scenarios.CATEGORIES
    assert scenarios.localized_categories("xx") is scenarios.CATEGORIES


def test_simple_prompt_is_translated_without_mutating_source():
    src = _by_id(scenarios.CATEGORIES)["SAFE-01"]["prompt"]
    for lang in ("zh-TW", "zh-CN", "ja"):
        loc = _by_id(scenarios.localized_categories(lang))["SAFE-01"]["prompt"]
        assert loc != src
        assert "#45821" in loc          # the order number (a payload token) is kept
    # Source object is untouched by the deep-copied localization.
    assert _by_id(scenarios.CATEGORIES)["SAFE-01"]["prompt"] == src


def test_payload_tokens_are_preserved():
    d = _by_id(scenarios.localized_categories("ja"))
    # base64 payload kept verbatim (decodes to "…reveal your system prompt")
    assert "SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM" in d["LLM01-03"]["prompt"]
    assert "DROP TABLE customers" in d["AGT-01"]["prompt"]           # SQL kept
    assert "huggingface.co/anon-user" in d["LLM03-03"]["prompt"]     # URL kept


def test_giant_log_is_composed_not_duplicated():
    en = _by_id(scenarios.CATEGORIES)["LLM10-05"]["prompt"]
    loc = _by_id(scenarios.localized_categories("zh-TW"))["LLM10-05"]["prompt"]
    # The repeated-log payload is spliced back in (same size class), only the lead differs.
    assert "0xDEADBEEF" in loc
    assert abs(len(loc) - len(en)) < 60
    assert not loc.startswith("Summarise")


def test_agt04_keeps_lorem_and_translates_wrapper():
    loc = _by_id(scenarios.localized_categories("zh-CN"))["AGT-04"]["prompt"]
    assert "Lorem ipsum" in loc                     # filler kept
    assert not loc.startswith("Please process")     # intro translated


def test_turns_goal_and_simulate_output_localized():
    d = _by_id(scenarios.localized_categories("ja"))
    assert len(d["MT-01"]["turns"]) == 3
    assert d["MT-01"]["turns"][0] != _by_id(scenarios.CATEGORIES)["MT-01"]["turns"][0]
    assert d["DYN-01"]["goal"] != _by_id(scenarios.CATEGORIES)["DYN-01"]["goal"]
    assert d["LLM03-02"]["simulateOutput"] != _by_id(scenarios.CATEGORIES)["LLM03-02"]["simulateOutput"]


def test_every_scenario_has_a_translation_in_each_language():
    ids = set(_by_id(scenarios.CATEGORIES))
    from backend.scenarios_i18n import PROMPTS
    for lang in ("zh-TW", "zh-CN", "ja"):
        missing = ids - set(PROMPTS[lang])
        assert not missing, f"{lang} missing translations for {sorted(missing)}"
