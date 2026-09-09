"""Tests for blockchain wallet lookup module."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from sources.blockchain import detect_wallet_type, lookup_wallet, BITCOIN_ADDRESS, ETHEREUM_ADDRESS, MONERO_ADDRESS


def test_detect_wallet_type_bitcoin_legacy():
    assert detect_wallet_type("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == BITCOIN_ADDRESS

def test_detect_wallet_type_bitcoin_bech32():
    assert detect_wallet_type("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == BITCOIN_ADDRESS

def test_detect_wallet_type_ethereum():
    assert detect_wallet_type("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") == ETHEREUM_ADDRESS

def test_detect_wallet_type_monero():
    addr = "4" + "A" * 94
    assert detect_wallet_type(addr) == MONERO_ADDRESS

def test_detect_wallet_type_unknown():
    assert detect_wallet_type("notawallet") is None

def test_detect_wallet_type_empty():
    assert detect_wallet_type("") is None


@pytest.mark.asyncio
async def test_lookup_monero_returns_gracefully():
    """Monero lookups should return without error, noting privacy."""
    addr = "4" + "A" * 94
    result = await lookup_wallet(addr)
    assert result["wallet_type"] == MONERO_ADDRESS
    assert result["lookup_successful"] is False
    assert "monero" in result.get("error", "").lower()


@pytest.mark.asyncio
async def test_lookup_bitcoin_handles_rate_limit():
    """Rate limit responses should be handled gracefully."""
    with patch("aiohttp.ClientSession.get") as mock_get:
        mock_response = AsyncMock()
        mock_response.status = 429
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)
        mock_get.return_value = mock_response
        
        from sources.blockchain import lookup_bitcoin_address
        result = await lookup_bitcoin_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
        assert result["lookup_successful"] is False
        assert result["error"] == "rate_limited"


@pytest.mark.asyncio
async def test_lookup_unknown_format():
    """Unrecognized address formats return gracefully."""
    result = await lookup_wallet("not-a-wallet-address")
    assert result["lookup_successful"] is False
    assert result["error"] == "unrecognized_format"
