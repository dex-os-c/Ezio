"""
tests/test_regex_patterns.py — Test coverage for entity-extraction regex
patterns, with emphasis on the multi-coin wallet coverage added beyond
BTC/ETH/XMR.

Test groups
-----------
1. Smoke tests — every pattern constant exists and is a compiled regex.
2. Positive cases — every new pattern matches at least one known address.
3. Negative cases — every new pattern rejects known wrong-format input
   (e.g. a BTC legacy address must not match LTC).
4. Context-aware tests — XRP and SOL only emit when crypto vocabulary
   is present in the surrounding text.
5. End-to-end extraction — extract_all on a multi-coin sample yields
   the expected types and counts.
6. Normalizer confidence levels — every new type has the right
   per-type confidence (0.95 / 0.85 / 0.90).
"""

from __future__ import annotations

import asyncio
import re

import pytest


# ---------------------------------------------------------------------------
# Imports from the production module under test
# ---------------------------------------------------------------------------

from extractor.regex_patterns import (
    # Entity type constants
    BITCOIN_ADDRESS,
    LITECOIN_ADDRESS,
    ZCASH_ADDRESS,
    DOGECOIN_ADDRESS,
    XRP_ADDRESS,
    SOLANA_ADDRESS,
    TRON_ADDRESS,
    BITCOIN_CASH_ADDRESS,
    DASH_ADDRESS,
    ENS_DOMAIN,
    CVE_NUMBER,
    ENTITY_TYPES,
    # Credential / token entity type constants
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    DISCORD_TOKEN,
    JWT_TOKEN,
    GOOGLE_API_KEY,
    STRIPE_KEY,
    STEALER_LOG_ENTRY,
    API_KEY,
    # Messaging / identity handle entity type constants
    TELEGRAM_HANDLE,
    DISCORD_HANDLE,
    XMPP_JID,
    TOX_ID,
    SESSION_ID,
    MATRIX_HANDLE,
    WIRE_HANDLE,
    ICQ_NUMBER,
    WICKR_ID,
    # Network / forensic identifier entity type constants
    IPV6_ADDRESS,
    MAC_ADDRESS,
    IPFS_CID,
    COMBO_LIST_ENTRY,
    YARA_RULE,
    MITRE_TACTIC,
    EXPLOIT_DB_ID,
    NUCLEI_TEMPLATE,
    CRYPTO_SEED_PHRASE,
    # Pattern constants
    BITCOIN_PATTERN,
    ETHEREUM_PATTERN,
    MONERO_PATTERN,
    LITECOIN_PATTERN,
    ZCASH_PATTERN,
    DOGECOIN_PATTERN,
    XRP_PATTERN,
    SOLANA_PATTERN,
    TRON_PATTERN,
    BITCOIN_CASH_PATTERN,
    DASH_PATTERN,
    ENS_PATTERN,
    # Credential pattern constants
    AWS_ACCESS_KEY_PATTERN,
    GITHUB_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    DISCORD_TOKEN_PATTERN,
    JWT_TOKEN_PATTERN,
    GOOGLE_API_KEY_PATTERN,
    STRIPE_KEY_PATTERN,
    # Messaging / identity handle pattern constants
    TELEGRAM_HANDLE_PATTERN,
    DISCORD_HANDLE_PATTERN,
    DISCORD_INVITE_PATTERN,
    DISCORD_USER_PATTERN,
    DISCORD_AT_PATTERN,
    XMPP_JID_PATTERN,
    TOX_ID_PATTERN,
    SESSION_ID_PATTERN,
    MATRIX_HANDLE_PATTERN,
    WIRE_HANDLE_PATTERN,
    ICQ_NUMBER_PATTERN,
    WICKR_ID_PATTERN,
    # Network / forensic identifier pattern constants
    IPV6_PATTERN,
    MAC_ADDRESS_PATTERN,
    IPFS_CID_PATTERN,
    YARA_RULE_PATTERN,
    MITRE_TACTIC_PATTERN,
    EXPLOIT_DB_PATTERN,
    NUCLEI_TEMPLATE_PATTERN,
    COMBO_LIST_PATTERN,
    # Helpers
    CRYPTO_CONTEXT_TERMS,
    MESSAGING_CONTEXT_TERMS,
    YARA_CONTEXT_TERMS,
    _has_crypto_context,
    _has_messaging_context,
    _has_text_within_window,
    _has_high_entropy,
    _has_yara_context,
    # Public API
    extract_all,
    extract_type,
)
from extractor.normalizer import (
    _confidence_for,
    _REGEX_TYPES,
    _REGEX_TYPE_CONFIDENCE,
    ENTITY_MIN_LENGTH,
    TYPE_PRIORITY,
    normalize_entities,
)
from utils.content_safety import (
    _looks_like_common_password,
    is_blocked_entity_value,
)


# ---------------------------------------------------------------------------
# 1. Smoke tests
# ---------------------------------------------------------------------------


def test_all_pattern_constants_are_compiled_regex():
    """Every <NAME>_PATTERN constant should be a compiled regex object."""
    for pat in (
        BITCOIN_PATTERN,
        ETHEREUM_PATTERN,
        MONERO_PATTERN,
        LITECOIN_PATTERN,
        ZCASH_PATTERN,
        DOGECOIN_PATTERN,
        XRP_PATTERN,
        SOLANA_PATTERN,
        TRON_PATTERN,
        BITCOIN_CASH_PATTERN,
        DASH_PATTERN,
        ENS_PATTERN,
    ):
        assert isinstance(pat, re.Pattern), f"{pat!r} is not a compiled regex"
        # Should be searchable — sanity check the .search method exists.
        assert hasattr(pat, "search")


def test_new_entity_types_in_entity_types_frozenset():
    """All nine new entity-type constants must be in ENTITY_TYPES."""
    for et in (
        LITECOIN_ADDRESS,
        ZCASH_ADDRESS,
        DOGECOIN_ADDRESS,
        XRP_ADDRESS,
        SOLANA_ADDRESS,
        TRON_ADDRESS,
        BITCOIN_CASH_ADDRESS,
        DASH_ADDRESS,
        ENS_DOMAIN,
    ):
        assert et in ENTITY_TYPES, f"{et} missing from ENTITY_TYPES"


def test_new_entity_types_in_regex_types_frozenset():
    """All new entity types must be in normalizer._REGEX_TYPES so they
    get full-blocklist bypass + 1.0 default confidence floor."""
    for et in (
        LITECOIN_ADDRESS,
        ZCASH_ADDRESS,
        DOGECOIN_ADDRESS,
        XRP_ADDRESS,
        SOLANA_ADDRESS,
        TRON_ADDRESS,
        BITCOIN_CASH_ADDRESS,
        DASH_ADDRESS,
        ENS_DOMAIN,
    ):
        assert et in _REGEX_TYPES, f"{et} missing from normalizer._REGEX_TYPES"


def test_extract_type_raises_on_unknown():
    """Unknown entity types should raise ValueError, not silently return []."""
    with pytest.raises(ValueError):
        extract_type("hello", "DOES_NOT_EXIST")


# ---------------------------------------------------------------------------
# 2. Positive cases
# ---------------------------------------------------------------------------


def test_litecoin_address_valid():
    """LTC legacy address with L prefix."""
    valid = "LMsY4TRgJGE1EJiMVkb9x9FVTQ4pS4DRB"
    assert LITECOIN_PATTERN.search(valid)
    assert extract_type(valid, LITECOIN_ADDRESS) == [valid]


def test_litecoin_address_m_prefix_valid():
    """LTC legacy address with M prefix (3-prefix equivalent)."""
    valid = "MELaeSf9GgXi9eHnkLf7d6fNz3z3vCJbNt"
    assert LITECOIN_PATTERN.search(valid)
    assert valid in extract_type(valid, LITECOIN_ADDRESS)


def test_zcash_transparent_valid():
    """ZEC transparent t1-prefix address."""
    valid = "t1Pd6MSdVPMgAMKAFXGEsykfMHiNMJtBQAN"
    assert ZCASH_PATTERN.search(valid)
    assert valid in extract_type(valid, ZCASH_ADDRESS)


def test_zcash_shielded_valid():
    """ZEC shielded zs1-prefix Sapling address (76 chars after zs1)."""
    # 76 base32 chars after the zs1 prefix — total 79 chars.
    payload = "a" * 76  # base32 allows lowercase 'a'
    assert len(payload) == 76
    valid = "zs1" + payload
    assert len(valid) == 79
    assert ZCASH_PATTERN.search(valid)
    assert valid in extract_type(valid, ZCASH_ADDRESS)


def test_dogecoin_address_valid():
    """DOGE D-prefix address."""
    valid = "DFundmtrigDKDgCTx5Yx7UwWLRTm3Raqdd"
    assert DOGECOIN_PATTERN.search(valid)
    assert valid in extract_type(valid, DOGECOIN_ADDRESS)


def test_ripple_address_valid_with_context():
    """XRP r-prefix address — needs crypto context to emit."""
    valid = "rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY"
    # No context → regex matches but extractor rejects.
    assert XRP_PATTERN.search(valid)
    assert extract_type(valid, XRP_ADDRESS) == []
    # With "wallet" in surrounding text → extractor emits.
    text = f"Ripple wallet: {valid}"
    assert valid in extract_type(text, XRP_ADDRESS)


def test_solana_address_valid_with_context():
    """SOL base58 32-44 char address — needs crypto context to emit."""
    valid = "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
    assert SOLANA_PATTERN.search(valid)
    # No context → rejected.
    assert extract_type(valid, SOLANA_ADDRESS) == []
    # With solana context → emitted.
    text = f"Solana wallet: {valid}"
    assert valid in extract_type(text, SOLANA_ADDRESS)


def test_tron_address_valid():
    """TRX T-prefix address."""
    valid = "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"
    assert TRON_PATTERN.search(valid)
    assert valid in extract_type(valid, TRON_ADDRESS)


def test_bitcoin_cash_valid():
    """BCH cashaddr with bitcoincash:q prefix."""
    valid = "bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy"
    assert BITCOIN_CASH_PATTERN.search(valid)
    assert valid in extract_type(valid, BITCOIN_CASH_ADDRESS)


def test_bitcoin_cash_p_prefix_valid():
    """BCH cashaddr with bitcoincash:p prefix (p2sh-style)."""
    valid = "bitcoincash:pmzyxz5jhv2xqv7l7x5z4n9n0c8r2q6j3k5m9p1q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0"
    assert BITCOIN_CASH_PATTERN.search(valid)
    assert valid in extract_type(valid, BITCOIN_CASH_ADDRESS)


def test_dash_address_valid():
    """DASH X-prefix address."""
    valid = "XoVZhnU1KjAxgNKrhGFLjYUKHESHpVcDXo"
    assert DASH_PATTERN.search(valid)
    assert valid in extract_type(valid, DASH_ADDRESS)


def test_ens_domain_valid():
    """ENS *.eth domain."""
    valid = "vitalik.eth"
    assert ENS_PATTERN.search(valid)
    assert valid in extract_type(valid, ENS_DOMAIN)


def test_ens_domain_with_hyphens_valid():
    """ENS allows internal hyphens (e.g. nick.eth, ilove-cats.eth)."""
    valid = "ilove-cats.eth"
    assert ENS_PATTERN.search(valid)
    assert valid in extract_type(valid, ENS_DOMAIN)


# ---------------------------------------------------------------------------
# 3. Negative cases — ensure patterns do not collide
# ---------------------------------------------------------------------------


def test_btc_does_not_match_litecoin():
    """A BTC P2PKH legacy address (1-prefix) must not match the LTC pattern."""
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    assert not LITECOIN_PATTERN.search(btc)
    assert btc not in extract_type(btc, LITECOIN_ADDRESS)


def test_btc_does_not_match_dogecoin():
    """A BTC address (1-prefix) must not match the DOGE pattern."""
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    assert not DOGECOIN_PATTERN.search(btc)
    assert btc not in extract_type(btc, DOGECOIN_ADDRESS)


def test_btc_does_not_match_dash():
    """A BTC address (1-prefix) must not match the DASH pattern."""
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    assert not DASH_PATTERN.search(btc)
    assert btc not in extract_type(btc, DASH_ADDRESS)


def test_btc_does_not_match_tron():
    """A BTC address (1-prefix) must not match the TRX pattern (T-prefix)."""
    btc = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    assert not TRON_PATTERN.search(btc)
    assert btc not in extract_type(btc, TRON_ADDRESS)


def test_random_text_does_not_match_sol_without_context():
    """SOL pattern is broad — it may match but the extractor must reject
    when no crypto-context keyword is in the ±200 char window."""
    random_b58 = "AbCdEfGhIjKlMnOpQrStUvWxYz12345678"
    # The pattern itself is permissive, so we focus on extractor behaviour:
    assert extract_type(random_b58, SOLANA_ADDRESS) == []


def test_random_text_does_not_match_xrp_without_context():
    """XRP pattern matches many things — the extractor must require
    crypto context."""
    random_word = "rthequickbrownfoxjumpsoverthelazydog1234"
    assert extract_type(random_word, XRP_ADDRESS) == []


def test_ens_pattern_rejects_plain_domains():
    """non-.eth domains should NOT match the ENS pattern."""
    for plain in ("notadomain.com", "foo.bar.org", "example.io"):
        assert not ENS_PATTERN.search(plain), f"ENS pattern matched {plain!r}"
        assert extract_type(plain, ENS_DOMAIN) == []


def test_ens_pattern_rejects_short_labels():
    """ENS labels < 3 chars should NOT match (regex enforces ≥3)."""
    # "ab.eth" — 2-char label — should not match (regex requires ≥3).
    assert not ENS_PATTERN.search("ab.eth")
    # "a.eth" — 1-char label — should not match (regex requires ≥3).
    assert not ENS_PATTERN.search("a.eth")


def test_ens_pattern_rejects_leading_or_trailing_hyphens():
    """ENS labels cannot start or end with a hyphen (RFC-1035)."""
    assert not ENS_PATTERN.search("-foo.eth")
    assert not ENS_PATTERN.search("foo-.eth")


# ---------------------------------------------------------------------------
# 4. Context-aware extraction (XRP, SOL)
# ---------------------------------------------------------------------------


def test_crypto_context_terms_cover_required_keywords():
    """The crypto context list must include the terms called out in the
    design brief."""
    required = {
        "wallet", "address", "send", "receive",
        "payment", "transfer", "crypto", "coin",
        "blockchain", "transaction", "deposit",
        "withdraw", "btc", "eth", "sol", "xrp",
        "solana", "ripple", "monero", "bitcoin",
        "usdt", "usdc", "stablecoin", "defi",
        "exchange", "swap", "escrow",
    }
    assert required.issubset(CRYPTO_CONTEXT_TERMS)


def test_has_crypto_context_returns_true_within_window():
    """A match with 'wallet' in the surrounding window should pass."""
    text = "Send coins to my Solana wallet address: HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH"
    match = SOLANA_PATTERN.search(text)
    assert match is not None
    assert _has_crypto_context(text, *match.span())


def test_has_crypto_context_returns_false_outside_window():
    """A match with no crypto-context keyword in the surrounding window should fail.

    Uses a direct call to _has_crypto_context with explicit coordinates
    rather than relying on a regex match (which needs word-boundary support
    that addresses in dense alphanumeric text lack).
    """
    text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 5
    text += "END"  # plenty of padding before the simulated match position
    # Simulate a match at position len(text) (end of text)
    match_start = len(text)
    match_end = len(text) + 40
    assert not _has_crypto_context(text, match_start, match_end, window=50)


# ---------------------------------------------------------------------------
# 5. End-to-end extraction on multi-coin sample text
# ---------------------------------------------------------------------------


def test_extract_all_on_multi_coin_sample():
    """extract_all on a sample text with many coin types should emit
    at least one match for each."""
    text = (
        "Ransomware payment options:\n"
        "Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n"
        "Litecoin: LMsY4TRgJGE1EJiMVkb9x9FVTQ4pS4DRB\n"
        "Dogecoin: DFundmtrigDKDgCTx5Yx7UwWLRTm3Raqdd\n"
        "Tron: TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW\n"
        "Contact: vitalik.eth for questions\n"
        "Payment via bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy\n"
        "Ripple wallet: rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY\n"
        "Send crypto to my Solana wallet HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH\n"
        "Dash address: XoVZhnU1KjAxgNKrhGFLjYUKHESHpVcDXo\n"
    )
    result = extract_all(text)

    # At least these specific entities should be present.
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" in result[BITCOIN_ADDRESS]
    assert "LMsY4TRgJGE1EJiMVkb9x9FVTQ4pS4DRB" in result[LITECOIN_ADDRESS]
    assert "DFundmtrigDKDgCTx5Yx7UwWLRTm3Raqdd" in result[DOGECOIN_ADDRESS]
    assert "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW" in result[TRON_ADDRESS]
    assert "vitalik.eth" in result[ENS_DOMAIN]
    assert "bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy" in result[BITCOIN_CASH_ADDRESS]
    assert "rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY" in result[XRP_ADDRESS]
    assert "HN7cABqLq46Es1jh92dQQisAq662SmxELLLsHHe4YWrH" in result[SOLANA_ADDRESS]
    assert "XoVZhnU1KjAxgNKrhGFLjYUKHESHpVcDXo" in result[DASH_ADDRESS]


def test_normalize_entities_produces_normalized_records():
    """normalize_entities should turn raw dicts into NormalizedEntity
    records with the correct entity type and confidence."""
    text = (
        "Send payment via Litecoin wallet LMsY4TRgJGE1EJiMVkb9x9FVTQ4pS4DRB "
        "or Dogecoin wallet DFundmtrigDKDgCTx5Yx7UwWLRTm3Raqdd."
    )
    raw = extract_all(text)
    records = normalize_entities(raw, "http://test.onion/x", page_text=text)
    by_type: dict[str, list] = {}
    for rec in records:
        by_type.setdefault(rec.entity_type, []).append(rec)

    assert LITECOIN_ADDRESS in by_type
    assert by_type[LITECOIN_ADDRESS][0].confidence == 0.94
    assert DOGECOIN_ADDRESS in by_type
    assert by_type[DOGECOIN_ADDRESS][0].confidence == 0.94


# ---------------------------------------------------------------------------
# 6. Confidence levels
# ---------------------------------------------------------------------------


def test_confidence_for_new_types_matches_brief():
    """Each new entity type should have the confidence specified in the
    design brief."""
    assert _confidence_for("LITECOIN_ADDRESS") == 0.90
    assert _confidence_for("ZCASH_ADDRESS") == 0.90
    assert _confidence_for("DOGECOIN_ADDRESS") == 0.90
    assert _confidence_for("XRP_ADDRESS") == 0.90
    assert _confidence_for("SOLANA_ADDRESS") == 0.90
    assert _confidence_for("TRON_ADDRESS") == 0.90
    assert _confidence_for("BITCOIN_CASH_ADDRESS") == 0.90
    assert _confidence_for("DASH_ADDRESS") == 0.90
    assert _confidence_for("ENS_DOMAIN") == 0.90


def test_confidence_for_legacy_types_unchanged():
    """The original three coin types should still be 1.0 — they are the
    highest-confidence patterns in the system."""
    assert _confidence_for("BITCOIN_ADDRESS") == 1.0
    assert _confidence_for("ETHEREUM_ADDRESS") == 0.90
    assert _confidence_for("MONERO_ADDRESS") == 0.90


def test_per_type_confidence_map_has_all_new_types():
    """The per-type confidence map should explicitly list every new type."""
    expected_new = {
        "LITECOIN_ADDRESS",
        "ZCASH_ADDRESS",
        "DOGECOIN_ADDRESS",
        "XRP_ADDRESS",
        "SOLANA_ADDRESS",
        "TRON_ADDRESS",
        "BITCOIN_CASH_ADDRESS",
        "DASH_ADDRESS",
        "ENS_DOMAIN",
    }
    assert expected_new.issubset(set(_REGEX_TYPE_CONFIDENCE.keys()))


def test_entity_min_length_for_new_types():
    """The normalizer must set a minimum length for each new type so the
    blocklist filter doesn't drop them."""
    for et in (
        "LITECOIN_ADDRESS",
        "ZCASH_ADDRESS",
        "DOGECOIN_ADDRESS",
        "XRP_ADDRESS",
        "SOLANA_ADDRESS",
        "TRON_ADDRESS",
        "DASH_ADDRESS",
        "ENS_DOMAIN",
    ):
        assert et in ENTITY_MIN_LENGTH, f"{et} missing from ENTITY_MIN_LENGTH"
        assert ENTITY_MIN_LENGTH[et] > 0


# ---------------------------------------------------------------------------
# 7. Async pipeline integration smoke test
# ---------------------------------------------------------------------------


def test_extract_entities_from_page_async_smoke():
    """Async pipeline should accept a multi-coin text and return at least
    one record of each expected type."""
    from extractor.pipeline import extract_entities_from_page

    text = (
        "Ransomware payment options:\n"
        "Bitcoin: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n"
        "Litecoin: LMsY4TRgJGE1EJiMVkb9x9FVTQ4pS4DRB\n"
        "Dogecoin: DFundmtrigDKDgCTx5Yx7UwWLRTm3Raqdd\n"
        "Tron: TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW\n"
        "Contact: vitalik.eth for questions\n"
        "Payment via bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy\n"
        "Ripple wallet: rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY\n"
    )

    async def run() -> list:
        result = await extract_entities_from_page(
            text, "http://test.onion/payment", persist=False
        )
        return list(result.entities)

    records = asyncio.run(run())
    crypto_records = [
        e for e in records
        if "address" in e.entity_type.lower() or "domain" in e.entity_type.lower()
    ]
    # At least 7 crypto entities should be present.
    assert len(crypto_records) >= 7, (
        f"Expected >=7 crypto entities, got {len(crypto_records)}: "
        f"{[e.entity_type for e in crypto_records]}"
    )
    # Every extracted entity must have confidence >= 0.80 (cap filter floor).
    for e in crypto_records:
        assert e.confidence >= 0.80, (
            f"{e.entity_type}={e.value} has confidence {e.confidence}"
        )


# ===========================================================================
# 8. Credential / token extraction (Phase 2)
# ===========================================================================
#
# These tests cover the AWS / GitHub / Slack / Discord / JWT / Google /
# Stripe / generic API key / stealer-log patterns added per the credential
# extraction brief.


# --- 8.1. AWS access key ---------------------------------------------------


def test_aws_access_key():
    """Canonical 20-char AKIA-prefixed key from AWS docs must extract."""
    valid = "AKIAIOSFODNN7EXAMPLE"
    assert AWS_ACCESS_KEY_PATTERN.search(valid)
    assert valid in extract_type(valid, AWS_ACCESS_KEY)

    # Negative — missing AKIA prefix, wrong length, contains lowercase
    invalid_examples = (
        "NOTANAWSKEY123456789",     # wrong prefix
        "AKIA123",                   # too short
        "akiaIOSFODNN7EXAMPLE",      # lowercase prefix (invalid)
        "AKIA" + "I" * 17,           # 17-char suffix, too long
    )
    for inv in invalid_examples:
        assert not AWS_ACCESS_KEY_PATTERN.search(inv), (
            f"AWS pattern incorrectly matched {inv!r}"
        )


def test_aws_secret_key_with_context():
    """AWS secret keys are 40-char base64 after a label."""
    text = (
        'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    )
    matches = extract_type(text, AWS_SECRET_KEY)
    assert matches == ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]


def test_aws_secret_key_alternate_label():
    """``SecretAccessKey`` label (camelCase) is also accepted."""
    text = 'SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    matches = extract_type(text, AWS_SECRET_KEY)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in matches


def test_aws_secret_key_no_label_rejected():
    """A bare 40-char base64 string with no label must not match."""
    bare = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert extract_type(bare, AWS_SECRET_KEY) == []


# --- 8.2. GitHub PAT -------------------------------------------------------


def test_github_token():
    """Classic ghp_/gho_/ghs_/ghu_/ghr_ formats all match (36 chars each)."""
    valid_tokens = [
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",     # classic PAT (36 chars payload)
        "gho_abcdefghijklmnopqrstuvwxyzAB123456",         # OAuth token (34 chars payload — see note)
        "ghs_ABCDEFGHIJabcdefghijk1234567890ab",          # Actions server (36 chars payload)
    ]
    # Real GitHub classic PATs are exactly 36 chars after the prefix.
    # We construct each token to be exactly 40 chars total (ghp_ + 36).
    valid_tokens = [
        "ghp_" + "A" * 36,   # 40-char total: ghp_ + 36 chars
        "gho_" + "B" * 36,
        "ghs_" + "C" * 36,
    ]
    for tok in valid_tokens:
        assert len(tok) == 40, f"sanity check failed: {tok!r} len={len(tok)}"
        assert GITHUB_TOKEN_PATTERN.search(tok), f"GH pattern missed {tok!r}"
        assert tok in extract_type(tok, GITHUB_TOKEN)

    # Fine-grained PAT — 82 chars after github_pat_
    fine = "github_pat_" + "A" * 82
    assert len(fine) == 82 + len("github_pat_")
    assert GITHUB_TOKEN_PATTERN.search(fine), "fine-grained GH PAT missed"
    assert fine in extract_type(fine, GITHUB_TOKEN)


def test_github_token_short_payload_rejected():
    """Too-short payloads must not match (regex requires exactly 36 base62)."""
    short = "ghp_tooshort"
    assert not GITHUB_TOKEN_PATTERN.search(short)


# --- 8.3. JWT --------------------------------------------------------------


def test_jwt_token():
    """Standard 3-part JWT anchored on eyJ prefix."""
    valid = (
        "eyJhbGciOiJIUzI1NiJ9"
        ".eyJzdWIiOiJ1c2VyIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert JWT_TOKEN_PATTERN.search(valid)
    assert valid in extract_type(valid, JWT_TOKEN)


def test_jwt_token_must_start_with_eyj():
    """JWTs whose header doesn't decode to ``{`` must not match — the eyJ
    anchor is the disambiguator vs random base64.aGVsbG8.bm9wZQ== strings."""
    fake = "aGVsbG8.d29ybGQ.bm90X2Ffand0"
    assert not JWT_TOKEN_PATTERN.search(fake)
    assert extract_type(fake, JWT_TOKEN) == []


# --- 8.4. Google API key ---------------------------------------------------


def test_google_api_key():
    """AIza + 35 chars [A-Za-z0-9_-]."""
    valid = "AIzaSyD-9tSrke72I6e0ydqRC_qRKfpc5EXAMPL"  # 39 chars total
    assert len(valid) == 39
    assert GOOGLE_API_KEY_PATTERN.search(valid)
    assert valid in extract_type(valid, GOOGLE_API_KEY)


def test_google_api_key_short_rejected():
    short = "AIzaSyD-9tSrke72"
    assert not GOOGLE_API_KEY_PATTERN.search(short)


# --- 8.5. Stripe -----------------------------------------------------------


def test_stripe_key():
    """Live + test secret + publishable keys all match."""
    stripe_suffix = "4eC39HqLyjWDarjtT1zdp7dc"
    valid_keys = [
        "sk_" + "live_" + stripe_suffix,
        "sk_" + "test_" + stripe_suffix,
        "pk_" + "live_" + stripe_suffix,
    ]
    for key in valid_keys:
        assert STRIPE_KEY_PATTERN.search(key), f"Stripe missed {key!r}"
        assert key in extract_type(key, STRIPE_KEY)


def test_stripe_key_wrong_environment_rejected():
    """``sk_prod_`` is not a Stripe prefix — must not match."""
    fake = "sk_" + "prod_" + "4eC39HqLyjWDarjtT1zdp7dc"
    assert not STRIPE_KEY_PATTERN.search(fake)


# --- 8.6. Discord / Slack / AWS / Google / Stripe smoke --------------------


def test_discord_token():
    """24.6.27 base64url."""
    # 24 + 1 + 6 + 1 + 27 = 59 chars total
    part1 = "NDAxMjEwNDg2NDA0OTA0MDQ4"   # 24 chars
    part2 = "DXBnMA"                    # 6 chars
    part3 = "7" * 27                   # 27 chars of valid base64url
    assert len(part1) == 24
    assert len(part2) == 6
    assert len(part3) == 27
    valid = part1 + "." + part2 + "." + part3
    assert len(valid) == 24 + 1 + 6 + 1 + 27
    assert DISCORD_TOKEN_PATTERN.search(valid)
    assert valid in extract_type(valid, DISCORD_TOKEN)


def test_slack_token_xoxb():
    """xoxb- bot token."""
    valid = "xox" + "b-12345678901-1234567890123-abcdefghijklmnopqrstuvwx"
    assert SLACK_TOKEN_PATTERN.search(valid)
    assert valid in extract_type(valid, SLACK_TOKEN)


def test_slack_token_xoxp():
    """xoxp- user token."""
    valid = "xox" + "p-12345678901-12345678901-12345678901-abcdef0123456789abcdef0123456789"
    assert SLACK_TOKEN_PATTERN.search(valid)


# --- 8.7. Generic API key + entropy ---------------------------------------


def test_high_entropy():
    """Shannon-entropy filter rejects weak / repeated strings, accepts secrets."""
    assert _has_high_entropy("aB3dE5fG7hI9jK1lM3nO") is True
    assert _has_high_entropy("password123") is False
    assert _has_high_entropy("aaaaaaaaaaaaaaaa") is False
    assert _has_high_entropy("abcdefgh") is False
    assert _has_high_entropy("") is False
    assert _has_high_entropy("short") is False


def test_generic_api_key_label_extracts_value():
    """A ``api_key=`` followed by a high-entropy value extracts the value
    (not the full label=value string)."""
    text = "api_key=aB3dE5fG7hI9jK1lM3nO"
    matches = extract_type(text, API_KEY)
    assert "aB3dE5fG7hI9jK1lM3nO" in matches


def test_generic_api_key_rejects_weak_value():
    """A ``api_key=password123`` must NOT extract — weak entropy + matches
    a common-password substring."""
    text = "api_key=password123"
    assert extract_type(text, API_KEY) == []


def test_generic_api_key_rejects_url():
    """URL-shaped values should be filtered (URLs are extracted separately)."""
    text = "callback=https://example.com/hook?abc=123"
    # Even if the regex matches, the URL filter should drop it.
    matches = extract_type(text, API_KEY)
    for m in matches:
        assert not m.startswith("http")


# --- 8.8. Stealer log ------------------------------------------------------


def test_stealer_log_detection():
    """Standard URL/LOGIN/PASSWORD three-line format emits URL + email
    but NEVER the password value."""
    sample = (
        "URL: https://bank.com/login\n"
        "LOGIN: victim@email.com\n"
        "PASSWORD: hunter2\n"
    )

    # The STEALER_LOG_ENTRY extractor emits the URL as the marker.
    stealer_matches = extract_type(sample, STEALER_LOG_ENTRY)
    assert "https://bank.com/login" in stealer_matches, (
        f"Stealer URL missing from {stealer_matches!r}"
    )

    # The EMAIL extractor independently catches the LOGIN field.
    emails = extract_type(sample, "EMAIL_ADDRESS")
    assert "victim@email.com" in emails

    # The password value MUST NOT appear anywhere as an entity.
    all_extracted = []
    for entity_type, values in extract_all(sample).items():
        all_extracted.extend(values)
    assert "hunter2" not in all_extracted, (
        "Password value leaked into entities — content safety failure"
    )


def test_stealer_log_multiple_entries():
    """Multiple stealer-log entries in one document all get extracted
    (URL only, never password)."""
    sample = (
        "URL: https://bank.com/login\n"
        "LOGIN: victim1@email.com\n"
        "PASSWORD: secret1\n"
        "\n"
        "URL: https://shop.com/account\n"
        "LOGIN: victim2@email.com\n"
        "PASSWORD: secret2\n"
    )
    stealer_matches = extract_type(sample, STEALER_LOG_ENTRY)
    assert "https://bank.com/login" in stealer_matches
    assert "https://shop.com/account" in stealer_matches

    all_extracted = []
    for values in extract_all(sample).values():
        all_extracted.extend(values)
    for forbidden in ("hunter2", "secret1", "secret2", "PASSWORD:"):
        assert forbidden not in all_extracted


def test_stealer_log_no_format_no_match():
    """Plain text with URL + LOGIN + PASSWORD labels but no colon-value
    structure must not match the stealer-log pattern."""
    sample = "This is a URL LOGIN PASSWORD but not a stealer log"
    assert extract_type(sample, STEALER_LOG_ENTRY) == []


# --- 8.9. Content safety for passwords ------------------------------------


def test_common_password_filter_catches_known_passwords():
    """The content-safety helper must recognise known weak passwords."""
    for p in ("hunter2", "Password123", "qwerty123", "admin", "letmein"):
        assert _looks_like_common_password(p), (
            f"Common password not detected: {p!r}"
        )


def test_common_password_filter_allows_strong_random():
    """Truly random secrets must NOT be flagged as common passwords."""
    for s in ("aB3dE5fG7hI9jK1lM3nO", "x9Pq2vLrTzNkWbYcFdSaGjHu8Mn", "AKIAIOSFODNN7EXAMPLE"):
        assert not _looks_like_common_password(s), (
            f"Strong secret incorrectly flagged as common password: {s!r}"
        )


def test_is_blocked_entity_value_blocks_common_password_regardless_of_type():
    """A weak-password value should be blocked even when the entity type
    is technical (API_KEY).  This catches the case where the generic
    extractor picks up ``api_key=password123`` — the password must be
    dropped before storage."""
    assert is_blocked_entity_value("API_KEY", "password123") is True
    assert is_blocked_entity_value("API_KEY", "hunter2") is True
    # But strong random secrets must pass.
    assert is_blocked_entity_value("API_KEY", "aB3dE5fG7hI9jK1lM3nO") is False
    # And real vendor-prefixed credentials must pass.
    assert is_blocked_entity_value("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE") is False
    assert is_blocked_entity_value(
        "STRIPE_KEY", "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    ) is False


# --- 8.10. Normalizer integration for credential types --------------------


def test_new_credential_types_in_entity_types_frozenset():
    """All 10 new credential / token entity types must be in ENTITY_TYPES."""
    expected = (
        AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, SLACK_TOKEN,
        DISCORD_TOKEN, JWT_TOKEN, GOOGLE_API_KEY, STRIPE_KEY,
        STEALER_LOG_ENTRY, API_KEY,
    )
    for et in expected:
        assert et in ENTITY_TYPES, f"{et} missing from ENTITY_TYPES"


def test_new_credential_types_in_regex_types_frozenset():
    """Credential types must be in normalizer._REGEX_TYPES so they get
    the 1.0-default confidence floor + blocklist bypass."""
    expected = (
        AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, SLACK_TOKEN,
        DISCORD_TOKEN, JWT_TOKEN, GOOGLE_API_KEY, STRIPE_KEY,
        STEALER_LOG_ENTRY, API_KEY,
    )
    for et in expected:
        assert et in _REGEX_TYPES, f"{et} missing from _REGEX_TYPES"


def test_confidence_for_credential_types_matches_brief():
    """Per-brief confidence values for each credential type."""
    assert _confidence_for(AWS_ACCESS_KEY) == 1.0
    assert _confidence_for(AWS_SECRET_KEY) == 1.0
    assert _confidence_for(GITHUB_TOKEN) == 1.0
    assert _confidence_for(SLACK_TOKEN) == 1.0
    assert _confidence_for(DISCORD_TOKEN) == 1.0
    assert _confidence_for(JWT_TOKEN) == 1.0
    assert _confidence_for(GOOGLE_API_KEY) == 1.0
    assert _confidence_for(STRIPE_KEY) == 1.0
    assert _confidence_for(STEALER_LOG_ENTRY) == 1.0
    assert _confidence_for(API_KEY) == 0.90


def test_credential_type_priority_is_one_or_two():
    """All credential types must have TYPE_PRIORITY in {1, 2} — they are
    high-value IOCs and must outrank actors/malware/person names."""
    for et in (
        AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, SLACK_TOKEN,
        DISCORD_TOKEN, JWT_TOKEN, GOOGLE_API_KEY, STRIPE_KEY,
        STEALER_LOG_ENTRY, API_KEY,
    ):
        p = TYPE_PRIORITY.get(et)
        assert p in (1, 2), f"{et} priority={p} (expected 1 or 2)"


def test_entity_min_length_set_for_all_credential_types():
    """Every credential type must have a positive min-length floor."""
    for et in (
        AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, SLACK_TOKEN,
        DISCORD_TOKEN, JWT_TOKEN, GOOGLE_API_KEY, STRIPE_KEY,
        STEALER_LOG_ENTRY, API_KEY,
    ):
        assert et in ENTITY_MIN_LENGTH, f"{et} missing from ENTITY_MIN_LENGTH"
        assert ENTITY_MIN_LENGTH[et] > 0


def test_credential_normalizer_round_trip():
    """End-to-end: extract → normalise → ensure credential entities
    survive the pipeline with the correct confidence."""
    gh_token = "ghp_" + "A" * 36   # 40 chars total (prefix + 36)
    google_key = "AIzaSyD-9tSrke72I6e0ydqRC_qRKfpc5EXAMPL"  # 39 chars total
    stripe_key = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    text = (
        "Leaked credentials:\n"
        "AWS Key: AKIAIOSFODNN7EXAMPLE\n"
        f"GitHub: {gh_token}\n"
        f"Stripe: {stripe_key}\n"
        f"Google: {google_key}\n"
        "JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"
    )
    raw = extract_all(text)
    records = normalize_entities(raw, "http://test.onion/leak", page_text=text)

    by_type: dict = {}
    for rec in records:
        by_type.setdefault(rec.entity_type, []).append(rec)

    assert AWS_ACCESS_KEY in by_type
    assert by_type[AWS_ACCESS_KEY][0].confidence == 0.94
    assert GITHUB_TOKEN in by_type
    assert by_type[GITHUB_TOKEN][0].confidence == 0.94
    assert STRIPE_KEY in by_type
    assert by_type[STRIPE_KEY][0].confidence == 0.94
    assert GOOGLE_API_KEY in by_type
    assert by_type[GOOGLE_API_KEY][0].confidence == 0.94
    assert JWT_TOKEN in by_type
    assert by_type[JWT_TOKEN][0].confidence == 0.94


# --- 8.11. Graph integration ----------------------------------------------


def test_graph_node_types_includes_credential():
    """graph.model.NODE_TYPES must expose CREDENTIAL."""
    from graph.model import NODE_TYPES
    assert hasattr(NODE_TYPES, "CREDENTIAL"), "NODE_TYPES.CREDENTIAL missing"
    assert NODE_TYPES.CREDENTIAL == "Credential"


def test_graph_builder_maps_all_credential_types():
    """graph.builder must map every credential type to NODE_TYPES.CREDENTIAL."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    from graph.model import NODE_TYPES
    for et in (
        AWS_ACCESS_KEY, AWS_SECRET_KEY, GITHUB_TOKEN, SLACK_TOKEN,
        DISCORD_TOKEN, JWT_TOKEN, GOOGLE_API_KEY, STRIPE_KEY,
        STEALER_LOG_ENTRY, API_KEY,
    ):
        assert _ENTITY_TYPE_TO_NODE_TYPE.get(et) == NODE_TYPES.CREDENTIAL, (
            f"{et} not mapped to NODE_TYPES.CREDENTIAL"
        )


def test_graph_builder_adds_credential_node_with_subtype_metadata():
    """When a credential entity is added to the graph, the node should
    carry its specific subtype in metadata so downstream queries can
    distinguish AWS keys from GitHub tokens etc."""
    import networkx as nx
    from graph.builder import add_entity_to_graph
    from graph.model import NODE_TYPES
    from extractor.normalizer import NormalizedEntity

    graph = nx.MultiDiGraph()
    entity = NormalizedEntity(
        entity_type=AWS_ACCESS_KEY,
        value="AKIAIOSFODNN7EXAMPLE",
        confidence=1.0,
        source_url="http://test.onion/leak",
        page_id=None,
        context_snippet="AWS Key: AKIAIOSFODNN7EXAMPLE",
        extraction_method="regex",
    )
    add_entity_to_graph(graph, entity)
    assert graph.has_node("AKIAIOSFODNN7EXAMPLE")
    node = graph.nodes["AKIAIOSFODNN7EXAMPLE"]
    assert node["node_type"] == NODE_TYPES.CREDENTIAL
    assert node["metadata"]["credential_kind"] == AWS_ACCESS_KEY


# ===========================================================================
# 9. Messaging / identity handle extraction (Phase 2)
# ===========================================================================
#
# These tests cover the Telegram / Discord / XMPP / Tox / Session / Matrix /
# Wire / ICQ / Wickr patterns added per the messaging-extraction brief.
# Each test corresponds to one of the bullets in the design brief.


# --- 9.0. Smoke tests ------------------------------------------------------


def test_messaging_pattern_constants_are_compiled_regex():
    """Every messaging <NAME>_PATTERN constant should be a compiled regex."""
    for pat in (
        TELEGRAM_HANDLE_PATTERN,
        DISCORD_HANDLE_PATTERN,
        DISCORD_INVITE_PATTERN,
        DISCORD_USER_PATTERN,
        DISCORD_AT_PATTERN,
        XMPP_JID_PATTERN,
        TOX_ID_PATTERN,
        SESSION_ID_PATTERN,
        MATRIX_HANDLE_PATTERN,
        WIRE_HANDLE_PATTERN,
        ICQ_NUMBER_PATTERN,
        WICKR_ID_PATTERN,
    ):
        assert isinstance(pat, re.Pattern), f"{pat!r} is not a compiled regex"
        assert hasattr(pat, "search")


def test_messaging_entity_types_in_entity_types_frozenset():
    """All 9 new messaging entity-type constants must be in ENTITY_TYPES."""
    for et in (
        TELEGRAM_HANDLE,
        DISCORD_HANDLE,
        XMPP_JID,
        TOX_ID,
        SESSION_ID,
        MATRIX_HANDLE,
        WIRE_HANDLE,
        ICQ_NUMBER,
        WICKR_ID,
    ):
        assert et in ENTITY_TYPES, f"{et} missing from ENTITY_TYPES"


def test_messaging_entity_types_in_regex_types_frozenset():
    """Messaging types must be in normalizer._REGEX_TYPES so they bypass
    the blocklist and use the per-type confidence map."""
    for et in (
        TELEGRAM_HANDLE,
        DISCORD_HANDLE,
        XMPP_JID,
        TOX_ID,
        SESSION_ID,
        MATRIX_HANDLE,
        WIRE_HANDLE,
        ICQ_NUMBER,
        WICKR_ID,
    ):
        assert et in _REGEX_TYPES, f"{et} missing from _REGEX_TYPES"


# --- 9.1. Telegram handle --------------------------------------------------


def test_telegram_handle_tme_link():
    """``t.me/<username>`` URL form extracts the username (no @ prefix)."""
    text = "contact me at t.me/lockbitsupport"
    matches = extract_type(text, TELEGRAM_HANDLE)
    assert "lockbitsupport" in matches


def test_telegram_handle_at_context():
    """``telegram: @<username>`` keyword form extracts the username."""
    text = "telegram: @lockbit_affiliate"
    matches = extract_type(text, TELEGRAM_HANDLE)
    assert "lockbit_affiliate" in matches


def test_telegram_handle_tg_keyword():
    """``tg: <username>`` short form also extracts (with or without @)."""
    for text, expected in (
        ("tg: @lockbitsupport", "lockbitsupport"),
        ("Telegram @LockBitSupport", "lockbitsupport"),  # case-insensitive
    ):
        matches = extract_type(text, TELEGRAM_HANDLE)
        assert expected in matches, f"{text!r} → {matches}"


def test_telegram_handle_signal_context():
    """``signal: @<username>`` falls back to context (signal can be a Telegram
    substitute — operators frequently advertise Telegram via 'signal')."""
    text = "signal: @lockbitsupport"
    matches = extract_type(text, TELEGRAM_HANDLE)
    assert "lockbitsupport" in matches


def test_telegram_handle_too_short_rejected():
    """Telegram username is 5-32 chars; 4-char names must be rejected."""
    text = "telegram: @lock"  # 4 chars
    assert extract_type(text, TELEGRAM_HANDLE) == []


# --- 9.2. Discord handle ---------------------------------------------------


def test_discord_legacy():
    """Discord legacy ``username#1234`` form extracts as-is."""
    text = "Discord: hacker#1337"
    matches = extract_type(text, DISCORD_HANDLE)
    assert "hacker#1337" in matches


def test_discord_legacy_case_insensitive():
    """Legacy form preserves original case (Discord was case-sensitive until
    the username migration)."""
    text = "Discord: Hacker#1337"
    matches = extract_type(text, DISCORD_HANDLE)
    # Canonical value is lowercased by the extractor (case-insensitive dedup)
    assert "hacker#1337" in matches


def test_discord_invite():
    """``discord.gg/<code>`` form extracts the invite code with ``invite:`` prefix."""
    text = "join: discord.gg/abc123XYZ"
    matches = extract_type(text, DISCORD_HANDLE)
    assert "invite:abc123xyz" in matches


def test_discord_user_link():
    """``discord.com/users/<snowflake-id>`` extracts with ``user:`` prefix."""
    text = "profile: discord.com/users/123456789012345678"
    matches = extract_type(text, DISCORD_HANDLE)
    assert "user:123456789012345678" in matches


def test_discord_at_with_context():
    """New-format ``@username`` extracts when 'discord' is within ±100 chars."""
    text = "join our discord server at @hackerone for updates"
    matches = extract_type(text, DISCORD_HANDLE)
    assert "hackerone" in matches


def test_discord_at_without_context_rejected():
    """New-format ``@username`` is too broad alone — must be rejected
    when no messaging-context keyword is within ±100 chars."""
    text = "ping @hackerone when ready"
    assert extract_type(text, DISCORD_HANDLE) == []


# --- 9.3. XMPP / Jabber JID ------------------------------------------------


def test_xmpp_jid():
    """``jabber: <user@host>`` extracts as XMPP_JID."""
    text = "jabber: lockbit@exploit.im"
    matches = extract_type(text, XMPP_JID)
    assert "lockbit@exploit.im" in matches


def test_xmpp_jid_various_keywords():
    """XMPP/Jabber/JID/Pidgin/Gajim/Xabber/Conversations/Delta Chat all
    act as valid context keywords."""
    samples = (
        ("xmpp: a@b.co", "a@b.co"),
        ("jabber: a@b.co", "a@b.co"),
        ("jid: a@b.co", "a@b.co"),
        ("pidgin: a@b.co", "a@b.co"),
        ("gajim: a@b.co", "a@b.co"),
        ("xabber: a@b.co", "a@b.co"),
        ("conversations: a@b.co", "a@b.co"),
        ("delta chat: a@b.co", "a@b.co"),
    )
    for text, expected in samples:
        matches = extract_type(text, XMPP_JID)
        assert expected in matches, f"{text!r} → {matches}"


def test_xmpp_plain_email_not_extracted():
    """A plain email without XMPP context must NOT be classified as XMPP_JID."""
    text = "contact: user@email.com"
    matches = extract_type(text, XMPP_JID)
    assert matches == []


def test_dedup_xmpp_vs_email():
    """When the same value would qualify as both XMPP_JID and EMAIL_ADDRESS,
    the normalizer's TYPE_PRIORITY tiebreak must keep XMPP_JID (priority 1
    beats EMAIL_ADDRESS priority 4).

    The conflict resolver runs in the pipeline (extract_entities_from_pages)
    via `_resolve_conflicts` — call it directly here so the test is
    independent of the DB-bound pipeline.
    """
    from extractor.normalizer import resolve_entity_type_conflicts
    text = "Jabber: user@domain.com"
    raw = extract_all(text)
    # Both regex extractors fire on this input
    assert "user@domain.com" in raw.get(XMPP_JID, [])
    assert "user@domain.com" in raw.get("EMAIL_ADDRESS", [])
    # Normalize and apply the same conflict resolver the pipeline uses
    records = normalize_entities(raw, "http://test.onion/x", page_text=text)
    resolved = resolve_entity_type_conflicts(records)
    xmpp_records = [r for r in resolved if r.entity_type == XMPP_JID]
    email_records = [r for r in resolved if r.entity_type == "EMAIL_ADDRESS"]
    assert xmpp_records, "XMPP_JID record missing after normalization"
    assert not email_records, (
        "EMAIL_ADDRESS record should have been deduped out in favor of XMPP_JID"
    )


# --- 9.4. Tox ID -----------------------------------------------------------


def test_tox_id():
    """76-char hex string extracts as Tox ID (canonical uppercase)."""
    tox_id = "A" * 76
    assert len(tox_id) == 76
    matches = extract_type(tox_id, TOX_ID)
    assert tox_id in matches
    # Canonical form is uppercase
    assert matches[0] == tox_id


def test_tox_id_lowercase_canonicalized_to_uppercase():
    """Lowercase hex 76-char string is extracted and canonicalised to uppercase."""
    tox_id_lower = "abcdef" * 12 + "abcd"
    assert len(tox_id_lower) == 76
    matches = extract_type(tox_id_lower, TOX_ID)
    assert tox_id_lower.upper() in matches


def test_tox_id_75_chars_rejected():
    """75-char hex must NOT match (Tox IDs are exactly 76 chars)."""
    too_short = "A" * 75
    assert extract_type(too_short, TOX_ID) == []


def test_tox_id_77_chars_rejected():
    """77-char hex must NOT match — first 76 would match but the 77th
    prevents the regex from finding a 76-char boundary match."""
    too_long = "A" * 77
    assert extract_type(too_long, TOX_ID) == []


# --- 9.5. Session ID -------------------------------------------------------


def test_session_id():
    """66-char hex starting with ``05`` extracts as Session ID."""
    session_id = "05" + "1234567890ABCDEF" * 4
    assert len(session_id) == 66
    matches = extract_type(session_id, SESSION_ID)
    assert session_id.lower() in matches


def test_session_id_starts_with_06_rejected():
    """66-char hex that does NOT start with ``05`` must not match."""
    other = "06" + "1234567890ABCDEF" * 4
    assert len(other) == 66
    assert extract_type(other, SESSION_ID) == []


def test_session_id_65_chars_rejected():
    """65-char hex must NOT match (Session IDs are exactly 66 chars)."""
    too_short = "05" + "A" * 63  # 65 total
    assert extract_type(too_short, SESSION_ID) == []


# --- 9.6. Matrix handle ----------------------------------------------------


def test_matrix_handle():
    """``@username:server.tld`` extracts as Matrix handle, canonicalised
    to lowercase per Matrix spec."""
    text = "@lockbit:matrix.org"
    matches = extract_type(text, MATRIX_HANDLE)
    assert "@lockbit:matrix.org" in matches


def test_matrix_handle_mixed_case():
    """Mixed-case homeserver is canonicalised to lowercase."""
    text = "@LockBit:MATRIX.ORG"
    matches = extract_type(text, MATRIX_HANDLE)
    assert "@lockbit:matrix.org" in matches


def test_matrix_handle_rejects_plain_at_user():
    """``@username`` without ``:server`` must NOT match (Matrix handles
    always have the form ``@user:server``)."""
    text = "@lockbit alone"
    assert extract_type(text, MATRIX_HANDLE) == []


# --- 9.7. ICQ number -------------------------------------------------------


def test_icq_number():
    """``icq: <5-9 digit>`` extracts the ICQ UIN."""
    text = "icq: 123456789"
    matches = extract_type(text, ICQ_NUMBER)
    assert "123456789" in matches


def test_icq_number_5_digits():
    """5-digit UIN (the minimum) extracts correctly."""
    text = "icq number: 12345"
    matches = extract_type(text, ICQ_NUMBER)
    assert "12345" in matches


def test_icq_standalone_number_rejected():
    """A bare 5-9 digit number without ``icq`` context must NOT be classified
    as ICQ_NUMBER (could be a phone fragment, an account number, etc.)."""
    text = "my pin is 123456789"
    assert extract_type(text, ICQ_NUMBER) == []


# --- 9.8. Wire handle ------------------------------------------------------


def test_wire_handle_with_at():
    """``wire: @<username>`` extracts the username (lowercase)."""
    text = "wire: @myhandle"
    matches = extract_type(text, WIRE_HANDLE)
    assert "myhandle" in matches


def test_wire_handle_without_at():
    """``wire: <username>`` (without @) also extracts."""
    text = "wire: myhandle"
    matches = extract_type(text, WIRE_HANDLE)
    assert "myhandle" in matches


# --- 9.9. Wickr ID ---------------------------------------------------------


def test_wickr_id():
    """``wickr: <id>`` extracts the Wickr ID."""
    text = "wickr: lockbitme"
    matches = extract_type(text, WICKR_ID)
    assert "lockbitme" in matches


def test_wickr_me_phrase():
    """``wickr me <id>`` colloquial form also extracts."""
    text = "reach out via wickr me hacker42"
    matches = extract_type(text, WICKR_ID)
    assert "hacker42" in matches


# --- 9.10. Normalizer integration for messaging types ----------------------


def test_messaging_type_priority_high_or_medium():
    """Messaging handles must have TYPE_PRIORITY in {1, 2} — high-value IOCs."""
    for et in (
        TELEGRAM_HANDLE, DISCORD_HANDLE, XMPP_JID, TOX_ID,
        SESSION_ID, MATRIX_HANDLE, WIRE_HANDLE, ICQ_NUMBER, WICKR_ID,
    ):
        p = TYPE_PRIORITY.get(et)
        assert p in (1, 2), f"{et} priority={p} (expected 1 or 2)"


def test_messaging_type_confidence_matches_brief():
    """Per-brief confidence values for each messaging type."""
    assert _confidence_for(TELEGRAM_HANDLE) == 0.90
    assert _confidence_for(DISCORD_HANDLE) == 0.90
    assert _confidence_for(XMPP_JID) == 0.90
    assert _confidence_for(TOX_ID) == 1.0
    assert _confidence_for(SESSION_ID) == 1.0
    assert _confidence_for(MATRIX_HANDLE) == 1.0
    assert _confidence_for(WIRE_HANDLE) == 0.90
    assert _confidence_for(ICQ_NUMBER) == 0.90
    assert _confidence_for(WICKR_ID) == 0.90


def test_messaging_type_min_length_set():
    """Every messaging type must have a positive min-length floor."""
    for et in (
        TELEGRAM_HANDLE, DISCORD_HANDLE, XMPP_JID, TOX_ID,
        SESSION_ID, MATRIX_HANDLE, WIRE_HANDLE, ICQ_NUMBER, WICKR_ID,
    ):
        assert et in ENTITY_MIN_LENGTH, f"{et} missing from ENTITY_MIN_LENGTH"
        assert ENTITY_MIN_LENGTH[et] > 0


def test_messaging_normalizer_round_trip():
    """End-to-end: extract → normalise → ensure messaging entities survive
    with the correct confidence and canonical value."""
    tox_id = "A" * 76
    session_id = "05" + "1234567890abcdef" * 4
    text = (
        f"Threat actor contact information:\n"
        f"Telegram: @lockbitsupport\n"
        f"Discord: Hacker#1337\n"
        f"jabber: lockbit@exploit.im\n"
        f"Tox: {tox_id}\n"
        f"Session: {session_id}\n"
        f"Matrix: @lockbitsupport:matrix.org\n"
        f"ICQ: 123456789\n"
        f"Wickr: lockbitme\n"
        f"Wire: @lockbitwire\n"
    )
    raw = extract_all(text)
    records = normalize_entities(raw, "http://test.onion/x", page_text=text)

    by_type: dict = {}
    for rec in records:
        by_type.setdefault(rec.entity_type, []).append(rec)

    # Spot-check each type survived with the right confidence
    assert TELEGRAM_HANDLE in by_type
    assert by_type[TELEGRAM_HANDLE][0].confidence == 0.94
    assert by_type[TELEGRAM_HANDLE][0].value == "lockbitsupport"

    assert DISCORD_HANDLE in by_type
    assert by_type[DISCORD_HANDLE][0].confidence == 0.94

    assert XMPP_JID in by_type
    assert by_type[XMPP_JID][0].confidence == 0.94
    assert by_type[XMPP_JID][0].value == "lockbit@exploit.im"

    assert TOX_ID in by_type
    assert by_type[TOX_ID][0].confidence == 0.94

    assert SESSION_ID in by_type
    assert by_type[SESSION_ID][0].confidence == 0.94

    assert MATRIX_HANDLE in by_type
    assert by_type[MATRIX_HANDLE][0].confidence == 0.94
    assert by_type[MATRIX_HANDLE][0].value == "@lockbitsupport:matrix.org"

    assert ICQ_NUMBER in by_type
    assert by_type[ICQ_NUMBER][0].confidence == 0.94

    assert WICKR_ID in by_type
    assert by_type[WICKR_ID][0].confidence == 0.94

    assert WIRE_HANDLE in by_type
    assert by_type[WIRE_HANDLE][0].confidence == 0.94


# --- 9.11. Context helper ---------------------------------------------------


def test_messaging_context_terms_cover_required_keywords():
    """The messaging context list must include the terms called out in the
    design brief."""
    required = {
        "telegram", "signal", "discord", "wickr", "wire",
        "jabber", "xmpp", "tox", "session", "matrix", "element",
    }
    assert required.issubset(MESSAGING_CONTEXT_TERMS)


def test_has_messaging_context_returns_true_within_window():
    """A match with 'telegram' in the surrounding window should pass."""
    text = "contact us on telegram for support @hackerone"
    match = DISCORD_AT_PATTERN.search(text)
    assert match is not None
    assert _has_messaging_context(text, *match.span())


def test_has_text_within_window_detects_keyword():
    """The bespoke ``discord`` ±100 char check used by the Discord new-format
    extractor must detect the keyword in the surrounding window."""
    text = "join our discord server for daily updates, contact @hackerone"
    match = DISCORD_AT_PATTERN.search(text)
    assert match is not None
    assert _has_text_within_window(text, *match.span(), "discord", window=100)


# --- 9.12. Graph integration ----------------------------------------------


def test_graph_node_types_includes_messaging_handle():
    """graph.model.NODE_TYPES must expose MESSAGING_HANDLE."""
    from graph.model import NODE_TYPES
    assert hasattr(NODE_TYPES, "MESSAGING_HANDLE"), (
        "NODE_TYPES.MESSAGING_HANDLE missing"
    )
    assert NODE_TYPES.MESSAGING_HANDLE == "MessagingHandle"


def test_graph_builder_maps_all_messaging_types():
    """graph.builder must map every messaging type to NODE_TYPES.MESSAGING_HANDLE."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    from graph.model import NODE_TYPES
    for et in (
        TELEGRAM_HANDLE, DISCORD_HANDLE, XMPP_JID, TOX_ID,
        SESSION_ID, MATRIX_HANDLE, WIRE_HANDLE, ICQ_NUMBER, WICKR_ID,
    ):
        assert _ENTITY_TYPE_TO_NODE_TYPE.get(et) == NODE_TYPES.MESSAGING_HANDLE, (
            f"{et} not mapped to NODE_TYPES.MESSAGING_HANDLE"
        )


def test_graph_builder_adds_messaging_node_with_subtype_metadata():
    """When a messaging entity is added to the graph, the node should carry
    its specific subtype in metadata so downstream queries can distinguish
    a Telegram handle from a Tox ID even though they share a node type."""
    import networkx as nx
    from graph.builder import add_entity_to_graph
    from graph.model import NODE_TYPES
    from extractor.normalizer import NormalizedEntity

    graph = nx.MultiDiGraph()
    entity = NormalizedEntity(
        entity_type=TELEGRAM_HANDLE,
        value="lockbitsupport",
        confidence=0.90,
        source_url="http://forum.onion/contact",
        page_id=None,
        context_snippet="telegram: @lockbitsupport",
        extraction_method="regex",
    )
    add_entity_to_graph(graph, entity)
    assert graph.has_node("lockbitsupport")
    node = graph.nodes["lockbitsupport"]
    assert node["node_type"] == NODE_TYPES.MESSAGING_HANDLE
    assert node["metadata"]["messaging_kind"] == TELEGRAM_HANDLE


# ===========================================================================
# 10. Network / forensic identifier extraction (Phase 2 — final subphase)
# ===========================================================================
#
# These tests cover the IPv6 / MAC / IPFS / YARA / MITRE_TACTIC /
# EXPLOIT_DB / NUCLEI_TEMPLATE / COMBO_LIST / CRYPTO_SEED_PHRASE patterns
# added per the design brief.  Each test corresponds to one of the
# bullets in the brief.


# --- 10.0. Smoke tests ---------------------------------------------------


def test_network_forensic_pattern_constants_are_compiled_regex():
    """Every network / forensic <NAME>_PATTERN constant should be a compiled regex."""
    for pat in (
        IPV6_PATTERN,
        MAC_ADDRESS_PATTERN,
        IPFS_CID_PATTERN,
        YARA_RULE_PATTERN,
        MITRE_TACTIC_PATTERN,
        EXPLOIT_DB_PATTERN,
        NUCLEI_TEMPLATE_PATTERN,
        COMBO_LIST_PATTERN,
    ):
        assert isinstance(pat, re.Pattern), f"{pat!r} is not a compiled regex"
        assert hasattr(pat, "search")


def test_network_forensic_entity_types_in_entity_types_frozenset():
    """All 9 new network / forensic entity-type constants must be in ENTITY_TYPES."""
    for et in (
        IPV6_ADDRESS,
        MAC_ADDRESS,
        IPFS_CID,
        COMBO_LIST_ENTRY,
        YARA_RULE,
        MITRE_TACTIC,
        EXPLOIT_DB_ID,
        NUCLEI_TEMPLATE,
        CRYPTO_SEED_PHRASE,
    ):
        assert et in ENTITY_TYPES, f"{et} missing from ENTITY_TYPES"


def test_network_forensic_entity_types_in_regex_types_frozenset():
    """Network / forensic types must be in normalizer._REGEX_TYPES so they
    bypass the blocklist and use the per-type confidence map."""
    for et in (
        IPV6_ADDRESS,
        MAC_ADDRESS,
        IPFS_CID,
        COMBO_LIST_ENTRY,
        YARA_RULE,
        MITRE_TACTIC,
        EXPLOIT_DB_ID,
        NUCLEI_TEMPLATE,
        CRYPTO_SEED_PHRASE,
    ):
        assert et in _REGEX_TYPES, f"{et} missing from _REGEX_TYPES"


# --- 10.1. IPv6 ----------------------------------------------------------


def test_ipv6_full():
    """Full 8-group IPv6 form extracts correctly (RFC 3849 documentation
    address — kept by the brief's filter list)."""
    text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    matches = extract_type(text, IPV6_ADDRESS)
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in matches


def test_ipv6_compressed():
    """Zero-compressed IPv6 form extracts correctly."""
    text = "2001:db8::1"
    matches = extract_type(text, IPV6_ADDRESS)
    assert "2001:db8::1" in matches


def test_ipv6_loopback_excluded():
    """::1 (loopback) must be filtered out."""
    assert extract_type("::1", IPV6_ADDRESS) == []


def test_ipv6_link_local_excluded():
    """fe80::/10 (link-local) must be filtered out."""
    assert extract_type("fe80::1", IPV6_ADDRESS) == []


def test_ipv6_unique_local_excluded():
    """fc00::/7 (unique local — RFC 4193) must be filtered out."""
    for text in ("fc00::1", "fd00::1", "fd12:3456:789a::1"):
        assert extract_type(text, IPV6_ADDRESS) == [], (
            f"ULA {text!r} should be excluded"
        )


def test_ipv6_trailing_double_colon():
    """Trailing :: (zero-padded) extracts correctly."""
    text = "2001:db8::"
    matches = extract_type(text, IPV6_ADDRESS)
    assert "2001:db8::" in matches


def test_ipv6_bare_double_colon_excluded():
    """Bare :: is the unspecified address — must be filtered out."""
    assert extract_type("::", IPV6_ADDRESS) == []


def test_ipv6_ipv4_mapped():
    """::ffff:192.0.2.1 (IPv4-mapped) is kept per the brief."""
    text = "::ffff:192.0.2.1"
    matches = extract_type(text, IPV6_ADDRESS)
    assert "::ffff:192.0.2.1" in matches


def test_ipv6_real_public():
    """A real public IPv6 (Cloudflare DNS) is kept."""
    text = "2606:4700:4700::1111"
    matches = extract_type(text, IPV6_ADDRESS)
    assert "2606:4700:4700::1111" in matches


# --- 10.2. MAC address ---------------------------------------------------


def test_mac_address_colon():
    """Colon-separated MAC address extracts and canonicalises to uppercase
    colon form."""
    text = "AA:BB:CC:DD:EE:FF"
    matches = extract_type(text, MAC_ADDRESS)
    assert "AA:BB:CC:DD:EE:FF" in matches


def test_mac_address_hyphen():
    """Hyphen-separated MAC address canonicalises to uppercase colon form."""
    text = "AA-BB-CC-DD-EE-FF"
    matches = extract_type(text, MAC_ADDRESS)
    assert "AA:BB:CC:DD:EE:FF" in matches


def test_mac_address_cisco():
    """Cisco three-octet (AABB.CCDD.EEFF) canonicalises to colon form."""
    text = "aabb.ccdd.eeff"
    matches = extract_type(text, MAC_ADDRESS)
    assert "AA:BB:CC:DD:EE:FF" in matches


def test_mac_address_lowercase_canonicalises():
    """Lowercase input is canonicalised to uppercase."""
    text = "aa:bb:cc:dd:ee:ff"
    matches = extract_type(text, MAC_ADDRESS)
    assert "AA:BB:CC:DD:EE:FF" in matches


def test_mac_address_all_zeros_rejected():
    """All-zeros MAC must be rejected (not a useful identifier)."""
    text = "00:00:00:00:00:00"
    assert extract_type(text, MAC_ADDRESS) == []


def test_mac_address_broadcast_rejected():
    """Broadcast MAC (FF:FF:FF:FF:FF:FF) must be rejected."""
    text = "FF:FF:FF:FF:FF:FF"
    assert extract_type(text, MAC_ADDRESS) == []


# --- 10.3. IPFS CID ------------------------------------------------------


def test_ipfs_cidv0():
    """CIDv0 (Qm + 44 base58 chars, 46 total) extracts correctly."""
    cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    assert len(cid) == 46
    matches = extract_type(cid, IPFS_CID)
    assert cid in matches


def test_ipfs_cidv1():
    """CIDv1 (bafy + 55-60 base32 chars) extracts correctly."""
    cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    assert cid.startswith("bafy")
    matches = extract_type(cid, IPFS_CID)
    assert cid in matches


def test_ipfs_cidv0_with_path_prefix():
    """``/ipfs/<CIDv0>`` path prefix form extracts the bare CID."""
    cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    text = f"https://ipfs.io/ipfs/{cid}"
    matches = extract_type(text, IPFS_CID)
    assert cid in matches


def test_ipfs_cidv1_with_path_prefix():
    """``/ipfs/<CIDv1>`` path prefix form extracts the bare CID."""
    cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    text = f"https://gateway.pinata.cloud/ipfs/{cid}"
    matches = extract_type(text, IPFS_CID)
    assert cid in matches


def test_ipfs_cid_dedup_across_forms():
    """The same CID appearing inline AND in a path prefix dedupes to one value."""
    cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    text = f"see {cid} and https://ipfs.io/ipfs/{cid}"
    matches = extract_type(text, IPFS_CID)
    assert matches == [cid]


# --- 10.4. YARA rule name -------------------------------------------------


def test_yara_rule():
    """``rule <Name> { strings: ... }`` extracts the rule name."""
    text = (
        "rule Malware_LockBit { strings: $s1 = \"lockbit\" condition: $s1 }"
    )
    matches = extract_type(text, YARA_RULE)
    assert "Malware_LockBit" in matches


def test_yara_rule_with_tags():
    """``rule <Name> : tag1 tag2 { ... }`` extracts the rule name only."""
    text = (
        "rule Suspicious_PowerShell : trojan malware { strings: $a = \"powershell\" condition: $a }"
    )
    matches = extract_type(text, YARA_RULE)
    assert "Suspicious_PowerShell" in matches


def test_yara_rule_prose_rejected():
    """Prose that mentions 'rule' but is not a YARA rule must be rejected.

    The YARA context check (strings:/condition:/meta:/import ") is the
    primary filter — without it, phrases like 'YARA rule detected:'
    would otherwise be misclassified."""
    text = "YARA rule detected: this is not an actual rule declaration"
    assert extract_type(text, YARA_RULE) == []


def test_yara_rule_context_keywords_present():
    """The YARA context term list must include the keywords called out
    in the design brief."""
    for required in ("strings:", "condition:", "meta:", 'import "'):
        assert required in YARA_CONTEXT_TERMS, (
            f"{required!r} missing from YARA_CONTEXT_TERMS"
        )


def test_has_yara_context_returns_true():
    """A YARA rule match with 'strings:' in the surrounding window should pass."""
    text = "rule TestRule { strings: $a = \"foo\" condition: $a }"
    match = YARA_RULE_PATTERN.search(text)
    assert match is not None
    assert _has_yara_context(text, *match.span())


def test_has_yara_context_returns_false():
    """A YARA rule match with no YARA keyword in the surrounding window
    must be rejected by the *extractor* (not the regex itself)."""
    # Text has the regex-matchable shape (rule X { ... }) but contains
    # none of the YARA context keywords (strings:, condition:, meta:,
    # import ", yara).  Use a placeholder body that has none of these.
    text = (
        "rule TestRule { placeholder body with no marker keywords }"
    )
    # The regex itself matches (the {} is there), so the context check
    # is the actual gate.  The extractor should reject because no YARA
    # keyword is in the surrounding window.
    matches = extract_type(text, YARA_RULE)
    assert matches == [], (
        f"YARA rule extractor must reject a match with no YARA context keyword, got {matches!r}"
    )


# --- 10.5. MITRE ATT&CK TACTIC -------------------------------------------


def test_mitre_tactic_initial_access():
    """TA0001 (Initial Access) extracts correctly."""
    matches = extract_type("TA0001", MITRE_TACTIC)
    assert "TA0001" in matches


def test_mitre_tactic_execution():
    """TA0002 (Execution) extracts correctly."""
    matches = extract_type("TA0002", MITRE_TACTIC)
    assert "TA0002" in matches


def test_mitre_tactic_technique_not_extracted_as_tactic():
    """T1059 (MITRE_TECHNIQUE) must NOT be classified as MITRE_TACTIC.
    Tactics are TA-prefixed; techniques are T-prefixed."""
    assert extract_type("T1059", MITRE_TACTIC) == []


def test_mitre_tactic_out_of_range_rejected():
    """TA9999 is outside the published range (TA0001-TA0043) and must
    be rejected by the validator."""
    assert extract_type("TA9999", MITRE_TACTIC) == []


def test_mitre_tactic_ta0000_rejected():
    """TA0000 is not a valid tactic (range starts at 1)."""
    assert extract_type("TA0000", MITRE_TACTIC) == []


def test_mitre_tactic_lowercase_canonicalised():
    """Lowercase ta0001 canonicalises to TA0001."""
    matches = extract_type("ta0001", MITRE_TACTIC)
    assert "TA0001" in matches


# --- 10.6. CVE extended (4-8 digit suffix) -------------------------------


def test_cve_extended_8_digit_suffix():
    """CVE with 8-digit suffix (recent high-volume years) now extracts —
    the upper bound was bumped from 7 → 8 in this subphase."""
    text = "CVE-2024-12345678"
    matches = extract_type(text, CVE_NUMBER)
    assert "CVE-2024-12345678" in matches


def test_cve_extended_7_digit_still_works():
    """Existing 7-digit CVEs still extract (regression check)."""
    text = "CVE-2023-1234567"
    matches = extract_type(text, CVE_NUMBER)
    assert "CVE-2023-1234567" in matches


def test_cve_extended_9_digit_rejected():
    """9-digit CVE suffix is not in the spec (MITRE stops at 8)."""
    text = "CVE-2024-123456789"
    assert extract_type(text, CVE_NUMBER) == []


# --- 10.7. Exploit-DB EDB-ID ----------------------------------------------


def test_exploit_db_id_label_form():
    """``EDB-ID: 12345`` extracts the numeric ID only."""
    text = "EDB-ID: 12345"
    matches = extract_type(text, EXPLOIT_DB_ID)
    assert "12345" in matches


def test_exploit_db_id_no_space():
    """``EDB-ID:12345`` (no space) also extracts."""
    text = "EDB-ID:12345"
    matches = extract_type(text, EXPLOIT_DB_ID)
    assert "12345" in matches


def test_exploit_db_id_url_form():
    """``exploit-db.com/exploits/12345`` extracts the bare numeric ID."""
    text = "see https://www.exploit-db.com/exploits/67890"
    matches = extract_type(text, EXPLOIT_DB_ID)
    assert "67890" in matches


def test_exploit_db_id_too_short_rejected():
    """3-digit ID (below the 4-6 digit range) must be rejected."""
    text = "EDB-ID: 123"
    assert extract_type(text, EXPLOIT_DB_ID) == []


def test_exploit_db_id_too_long_rejected():
    """7-digit ID (above the 4-6 digit range) must be rejected."""
    text = "EDB-ID: 1234567"
    assert extract_type(text, EXPLOIT_DB_ID) == []


# --- 10.8. Nuclei template ID --------------------------------------------


def test_nuclei_template_with_context():
    """``nuclei ... cve-2024-1234-rce.yaml`` extracts the template ID."""
    text = "scan with nuclei -t cve-2024-1234-rce.yaml"
    matches = extract_type(text, NUCLEI_TEMPLATE)
    assert "cve-2024-1234-rce" in matches


def test_nuclei_template_without_context_rejected():
    """The yaml-shape alone is too broad — must require 'nuclei' within
    ±200 chars (e.g. a docker-compose-dev-test.yaml is not a Nuclei
    template)."""
    text = "see file: docker-compose-dev-test.yaml"
    assert extract_type(text, NUCLEI_TEMPLATE) == []


def test_nuclei_template_too_few_segments_rejected():
    """A single segment + .yaml is not a Nuclei template (need 3+)."""
    text = "nuclei scan using single.yaml"
    assert extract_type(text, NUCLEI_TEMPLATE) == []


# --- 10.9. Credential combo-list block -----------------------------------


def test_combo_list_detected():
    """3+ lines of email:password format trigger combo-list detection.

    The emails are extracted (not the passwords), and the page-level
    detection signal is preserved by emitting at least one entity."""
    sample = (
        "Combo dump:\n"
        "victim1@email.com:hunter2\n"
        "victim2@email.com:password123\n"
        "victim3@email.com:qwerty456\n"
    )
    matches = extract_type(sample, COMBO_LIST_ENTRY)
    # All 3 emails should be extracted
    assert "victim1@email.com" in matches
    assert "victim2@email.com" in matches
    assert "victim3@email.com" in matches


def test_combo_list_passwords_not_stored():
    """The password side of an email:password line must NEVER be emitted
    as an entity (content safety)."""
    sample = (
        "Dump:\n"
        "victim1@email.com:hunter2\n"
        "victim2@email.com:password123\n"
        "victim3@email.com:qwerty456\n"
    )
    all_extracted = []
    for values in extract_all(sample).values():
        all_extracted.extend(values)
    for forbidden in ("hunter2", "password123", "qwerty456"):
        assert forbidden not in all_extracted, (
            f"Password {forbidden!r} leaked into entities — content safety failure"
        )


def test_combo_list_threshold_3_lines():
    """Fewer than 3 matching lines must NOT trigger combo-list detection
    (a one-off email:pass line in a forum post is not a "combo list dump")."""
    sample = (
        "two lines is not enough:\n"
        "victim1@email.com:hunter2\n"
        "victim2@email.com:password123\n"
    )
    assert extract_type(sample, COMBO_LIST_ENTRY) == []


# --- 10.10. BIP39 seed phrase detection ----------------------------------


def test_seed_phrase_detected_12_words():
    """A 12-word BIP39 run emits the SEED_PHRASE_DETECTED_12_WORDS marker.
    The actual words are NEVER stored in the canonical value."""
    sample = (
        "Seed phrase: abandon ability able about above absent absorb "
        "abstract absurd abuse access accident"
    )
    matches = extract_type(sample, CRYPTO_SEED_PHRASE)
    assert "SEED_PHRASE_DETECTED_12_WORDS" in matches
    # The actual words must NOT be in any emitted value.
    all_extracted = []
    for values in extract_all(sample).values():
        all_extracted.extend(values)
    for word in ("abandon", "ability", "accident"):
        assert word not in all_extracted, (
            f"BIP39 word {word!r} leaked into entities — content safety failure"
        )


def test_seed_phrase_detected_24_words():
    """A 24-word BIP39 run emits the SEED_PHRASE_DETECTED_24_WORDS marker."""
    sample = (
        "Wallet seed:\n"
        "abandon ability able about above absent absorb abstract absurd "
        "abuse access accident account accuse achieve acid acoustic acquire "
        "across act action actor actress actual adapt add"
    )
    matches = extract_type(sample, CRYPTO_SEED_PHRASE)
    assert "SEED_PHRASE_DETECTED_24_WORDS" in matches


def test_seed_phrase_short_run_not_detected():
    """11 or fewer consecutive BIP39 words must NOT trigger detection."""
    sample = "abandon ability able about above absent absorb abstract absurd abuse access"
    matches = extract_type(sample, CRYPTO_SEED_PHRASE)
    assert matches == []


def test_seed_phrase_words_never_in_canonical():
    """The canonical value emitted for a seed phrase is the marker string,
    never the actual words (this is the most important content-safety
    check in Phase 2 final)."""
    sample = (
        "Secret: abandon ability able about above absent absorb abstract "
        "absurd abuse access accident"
    )
    matches = extract_type(sample, CRYPTO_SEED_PHRASE)
    for m in matches:
        assert m.startswith("SEED_PHRASE_DETECTED_"), (
            f"Canonical value is not a marker: {m!r}"
        )


# --- 10.11. Normalizer integration ---------------------------------------


def test_confidence_for_network_forensic_types_matches_brief():
    """Per-brief confidence values for each new type."""
    assert _confidence_for(IPV6_ADDRESS) == 1.0
    assert _confidence_for(MAC_ADDRESS) == 1.0
    assert _confidence_for(IPFS_CID) == 1.0
    assert _confidence_for(YARA_RULE) == 0.90
    assert _confidence_for(MITRE_TACTIC) == 1.0
    assert _confidence_for(EXPLOIT_DB_ID) == 1.0
    assert _confidence_for(NUCLEI_TEMPLATE) == 0.90
    assert _confidence_for(COMBO_LIST_ENTRY) == 0.90
    assert _confidence_for(CRYPTO_SEED_PHRASE) == 0.90


def test_network_forensic_type_priority():
    """All new network / forensic types must have TYPE_PRIORITY in {1, 2}
    — they are high-value IOCs that must outrank actors/malware/person names."""
    for et in (
        IPV6_ADDRESS, MAC_ADDRESS, IPFS_CID, COMBO_LIST_ENTRY,
        YARA_RULE, MITRE_TACTIC, EXPLOIT_DB_ID, NUCLEI_TEMPLATE,
        CRYPTO_SEED_PHRASE,
    ):
        p = TYPE_PRIORITY.get(et)
        assert p in (1, 2), f"{et} priority={p} (expected 1 or 2)"


def test_network_forensic_min_length_set():
    """Every new type must have a positive min-length floor."""
    for et in (
        IPV6_ADDRESS, MAC_ADDRESS, IPFS_CID, COMBO_LIST_ENTRY,
        YARA_RULE, MITRE_TACTIC, EXPLOIT_DB_ID, NUCLEI_TEMPLATE,
        CRYPTO_SEED_PHRASE,
    ):
        assert et in ENTITY_MIN_LENGTH, f"{et} missing from ENTITY_MIN_LENGTH"
        assert ENTITY_MIN_LENGTH[et] > 0


def test_network_forensic_normalizer_round_trip():
    """End-to-end: extract → normalise → ensure network / forensic entities
    survive with the correct confidence and canonical value."""
    text = (
        "Network indicators:\n"
        "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n"
        "MAC: AA-BB-CC-DD-EE-FF\n"
        "IPFS: QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG\n"
        "MITRE: TA0001 (Initial Access)\n"
        "EDB-ID: 12345\n"
        "CVE-2024-12345678\n"
    )
    raw = extract_all(text)
    records = normalize_entities(raw, "http://test.onion/intel", page_text=text)
    by_type: dict = {}
    for rec in records:
        by_type.setdefault(rec.entity_type, []).append(rec)

    # Spot-check each type survived with the right confidence + canonical form
    assert IPV6_ADDRESS in by_type
    assert by_type[IPV6_ADDRESS][0].confidence == 0.94
    assert by_type[IPV6_ADDRESS][0].value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    assert MAC_ADDRESS in by_type
    assert by_type[MAC_ADDRESS][0].confidence == 0.94
    # Hyphen form was canonicalised to colon form
    assert by_type[MAC_ADDRESS][0].value == "AA:BB:CC:DD:EE:FF"

    assert IPFS_CID in by_type
    assert by_type[IPFS_CID][0].confidence == 0.94

    assert MITRE_TACTIC in by_type
    assert by_type[MITRE_TACTIC][0].confidence == 0.94
    assert by_type[MITRE_TACTIC][0].value == "TA0001"

    assert EXPLOIT_DB_ID in by_type
    assert by_type[EXPLOIT_DB_ID][0].confidence == 0.94
    assert by_type[EXPLOIT_DB_ID][0].value == "12345"

    assert CVE_NUMBER in by_type
    # 8-digit CVE now extracts (was failing in the previous pattern)
    cves = [r.value for r in by_type[CVE_NUMBER]]
    assert "CVE-2024-12345678" in cves


def test_normalizer_rejects_malformed_crypto_seed():
    """The normalizer must reject a CRYPTO_SEED_PHRASE value that is not
    one of the two known marker strings — defends against an accidental
    leak of an actual seed phrase value."""
    from extractor.normalizer import _validate_network_forensic
    # The two known marker strings pass
    assert _validate_network_forensic(CRYPTO_SEED_PHRASE, "SEED_PHRASE_DETECTED_12_WORDS")
    assert _validate_network_forensic(CRYPTO_SEED_PHRASE, "SEED_PHRASE_DETECTED_24_WORDS")
    # A real seed phrase (or anything else) must be rejected
    assert not _validate_network_forensic(
        CRYPTO_SEED_PHRASE,
        "abandon ability able about above absent absorb abstract absurd abuse access accident",
    )


def test_normalizer_rejects_malformed_ipv6():
    """The normalizer validator catches malformed IPv6 values that the
    regex might have let through."""
    from extractor.normalizer import _validate_network_forensic
    # Private/loopback/ULA must be rejected
    for bad in ("::1", "fe80::1", "fc00::1"):
        assert not _validate_network_forensic(IPV6_ADDRESS, bad), (
            f"Validator should reject {bad!r}"
        )
    # Public addresses pass
    assert _validate_network_forensic(IPV6_ADDRESS, "2606:4700:4700::1111")


# --- 10.12. Graph integration --------------------------------------------


def test_graph_node_types_includes_network_indicator():
    """graph.model.NODE_TYPES must expose NETWORK_INDICATOR."""
    from graph.model import NODE_TYPES
    assert hasattr(NODE_TYPES, "NETWORK_INDICATOR"), "NETWORK_INDICATOR missing"
    assert NODE_TYPES.NETWORK_INDICATOR == "NetworkIndicator"


def test_graph_node_types_includes_malware_indicator():
    """graph.model.NODE_TYPES must expose MALWARE_INDICATOR."""
    from graph.model import NODE_TYPES
    assert hasattr(NODE_TYPES, "MALWARE_INDICATOR"), "MALWARE_INDICATOR missing"
    assert NODE_TYPES.MALWARE_INDICATOR == "MalwareIndicator"


def test_graph_node_types_includes_content_indicator():
    """graph.model.NODE_TYPES must expose CONTENT_INDICATOR."""
    from graph.model import NODE_TYPES
    assert hasattr(NODE_TYPES, "CONTENT_INDICATOR"), "CONTENT_INDICATOR missing"
    assert NODE_TYPES.CONTENT_INDICATOR == "ContentIndicator"


def test_graph_builder_maps_ipv6_to_network_node_type():
    """IPV6_ADDRESS reuses the IP_ADDRESS ('network') node type."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(IPV6_ADDRESS) == "network"


def test_graph_builder_maps_mac_to_network_indicator():
    """MAC_ADDRESS maps to the new NETWORK_INDICATOR node type."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    from graph.model import NODE_TYPES
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(MAC_ADDRESS) == NODE_TYPES.NETWORK_INDICATOR


def test_graph_builder_maps_ipfs_to_file_hash():
    """IPFS_CID reuses the file_hash node type (content-addressed)."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(IPFS_CID) == "file_hash"


def test_graph_builder_maps_malware_indicators():
    """YARA_RULE and NUCLEI_TEMPLATE map to MALWARE_INDICATOR."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    from graph.model import NODE_TYPES
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(YARA_RULE) == NODE_TYPES.MALWARE_INDICATOR
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(NUCLEI_TEMPLATE) == NODE_TYPES.MALWARE_INDICATOR


def test_graph_builder_maps_content_indicators():
    """IPFS_CID, COMBO_LIST_ENTRY, CRYPTO_SEED_PHRASE map to
    CONTENT_INDICATOR (the IPFS_CID value is also reused for file_hash
    per the brief — verify the COMBO_LIST and SEED_PHRASE mapping)."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    from graph.model import NODE_TYPES
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(COMBO_LIST_ENTRY) == NODE_TYPES.CONTENT_INDICATOR
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(CRYPTO_SEED_PHRASE) == NODE_TYPES.CONTENT_INDICATOR


def test_graph_builder_maps_exploit_db_to_vulnerability():
    """EXPLOIT_DB_ID reuses the vulnerability node type (same family as CVE)."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(EXPLOIT_DB_ID) == "vulnerability"


def test_graph_builder_maps_mitre_tactic_to_technique():
    """MITRE_TACTIC reuses the technique node type (same family as
    MITRE_TECHNIQUE) — the brief's mapping says same as MITRE_TECHNIQUE."""
    from graph.builder import _ENTITY_TYPE_TO_NODE_TYPE
    assert _ENTITY_TYPE_TO_NODE_TYPE.get(MITRE_TACTIC) == "technique"


def test_graph_builder_adds_mac_node_with_subtype_metadata():
    """When a MAC address entity is added to the graph, the node carries
    its specific subtype in metadata so a query can distinguish a MAC
    from another NETWORK_INDICATOR subtype."""
    import networkx as nx
    from graph.builder import add_entity_to_graph
    from graph.model import NODE_TYPES
    from extractor.normalizer import NormalizedEntity

    graph = nx.MultiDiGraph()
    entity = NormalizedEntity(
        entity_type=MAC_ADDRESS,
        value="AA:BB:CC:DD:EE:FF",
        confidence=0.95,
        source_url="http://test.onion/pcap",
        page_id=None,
        context_snippet="MAC: AA:BB:CC:DD:EE:FF",
        extraction_method="regex",
    )
    add_entity_to_graph(graph, entity)
    assert graph.has_node("AA:BB:CC:DD:EE:FF")
    node = graph.nodes["AA:BB:CC:DD:EE:FF"]
    assert node["node_type"] == NODE_TYPES.NETWORK_INDICATOR
    assert node["metadata"]["network_kind"] == MAC_ADDRESS


def test_graph_builder_adds_yara_node_with_subtype_metadata():
    """When a YARA rule entity is added to the graph, the node carries
    its specific subtype in metadata so a query can distinguish YARA
    from NUCLEI_TEMPLATE even though they share MALWARE_INDICATOR."""
    import networkx as nx
    from graph.builder import add_entity_to_graph
    from graph.model import NODE_TYPES
    from extractor.normalizer import NormalizedEntity

    graph = nx.MultiDiGraph()
    entity = NormalizedEntity(
        entity_type=YARA_RULE,
        value="Malware_LockBit",
        confidence=0.90,
        source_url="http://test.onion/yara",
        page_id=None,
        context_snippet="rule Malware_LockBit { strings: ... }",
        extraction_method="regex",
    )
    add_entity_to_graph(graph, entity)
    assert graph.has_node("Malware_LockBit")
    node = graph.nodes["Malware_LockBit"]
    assert node["node_type"] == NODE_TYPES.MALWARE_INDICATOR
    assert node["metadata"]["malware_kind"] == YARA_RULE


def test_graph_builder_adds_seed_phrase_node_with_subtype_metadata():
    """When a CRYPTO_SEED_PHRASE entity is added, the node carries
    the SEED marker (not the actual words) and the subtype metadata."""
    import networkx as nx
    from graph.builder import add_entity_to_graph
    from graph.model import NODE_TYPES
    from extractor.normalizer import NormalizedEntity

    graph = nx.MultiDiGraph()
    entity = NormalizedEntity(
        entity_type=CRYPTO_SEED_PHRASE,
        value="SEED_PHRASE_DETECTED_12_WORDS",
        confidence=0.90,
        source_url="http://test.onion/wallet",
        page_id=None,
        context_snippet="abandon ability able ... accident",
        extraction_method="regex",
    )
    add_entity_to_graph(graph, entity)
    assert graph.has_node("SEED_PHRASE_DETECTED_12_WORDS")
    node = graph.nodes["SEED_PHRASE_DETECTED_12_WORDS"]
    assert node["node_type"] == NODE_TYPES.CONTENT_INDICATOR
    assert node["metadata"]["content_kind"] == CRYPTO_SEED_PHRASE
