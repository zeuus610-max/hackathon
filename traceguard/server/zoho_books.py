"""Zoho Books India vendor bank-account adapter."""
from __future__ import annotations

import os
from urllib.parse import quote

import httpx


class ZohoBooksError(Exception):
    """Safe provider error without credential or bank data."""


def configuration() -> tuple[str, str, str, str]:
    organization_id = os.getenv("ORBIT_ZOHO_ORGANIZATION_ID", "").strip()
    access_token = os.getenv("ORBIT_ZOHO_ACCESS_TOKEN", "").strip()
    contact_id = os.getenv("ORBIT_ZOHO_VENDOR_ID_MAP_JSON", "")
    if not organization_id or not access_token or not contact_id:
        raise ZohoBooksError("Zoho Books India credentials, organization, and vendor map are required")
    import json
    try:
        mapping = json.loads(contact_id)
        if not isinstance(mapping, dict) or not all(isinstance(k, str) and str(v).isdigit() for k, v in mapping.items()):
            raise ValueError
    except (ValueError, TypeError):
        raise ZohoBooksError("Zoho Books vendor ID map is invalid")
    return organization_id, access_token, os.getenv("ORBIT_ZOHO_API_BASE", "https://www.zohoapis.in/books/v3").rstrip("/"), mapping


async def _access_token(client: httpx.AsyncClient, configured_token: str) -> str:
    """Refresh Zoho's short-lived access token when a refresh token is configured."""
    refresh_token = os.getenv("ORBIT_ZOHO_REFRESH_TOKEN", "").strip()
    client_id = os.getenv("ORBIT_ZOHO_CLIENT_ID", "").strip()
    client_secret = os.getenv("ORBIT_ZOHO_CLIENT_SECRET", "").strip()
    if not (refresh_token and client_id and client_secret):
        return configured_token
    try:
        response = await client.post(
            "https://accounts.zoho.in/oauth/v2/token",
            data={"grant_type": "refresh_token", "client_id": client_id,
                  "client_secret": client_secret, "refresh_token": refresh_token},
        )
        response.raise_for_status()
        result = response.json()
        token = result.get("access_token")
        if not token:
            raise ValueError("missing access token")
        return token
    except (httpx.HTTPError, ValueError, AttributeError) as exc:
        raise ZohoBooksError("Zoho Books token refresh failed") from exc


async def apply_vendor_bank_details(*, vendor_id: str, bank_details: dict) -> dict:
    organization_id, token, base, mapping = configuration()
    contact_id = mapping.get(vendor_id)
    if not contact_id:
        raise ZohoBooksError("Orbit vendor is not mapped to a Zoho Books contact")
    if bank_details.get("country", "").upper() != "IN":
        raise ZohoBooksError("Zoho Books India adapter accepts India bank accounts only")
    url = f"{base}/contacts/{quote(contact_id, safe='')}/bankaccount?organization_id={quote(organization_id, safe='')}"
    payload = {"account_number": bank_details["account_number"],
               "routing_number": bank_details["routing_code"],
               "bank_name": bank_details["bank_name"],
               "name": bank_details["account_holder"],
               "beneficiary_name": bank_details["account_holder"]}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15, connect=4)) as client:
            token = await _access_token(client, token)
            response = await client.post(url, headers={"Authorization": f"Zoho-oauthtoken {token}"}, json=payload)
    except httpx.HTTPError as exc:
        raise ZohoBooksError("Zoho Books India request failed") from exc
    if not 200 <= response.status_code < 300:
        raise ZohoBooksError(f"Zoho Books India returned HTTP {response.status_code}")
    try:
        result = response.json()
        account = result.get("bank_account", {})
        if result.get("code") != 0 or not account.get("bank_account_id"):
            raise ValueError
    except (ValueError, AttributeError):
        raise ZohoBooksError("Zoho Books did not confirm the vendor bank account")
    return {"status_code": response.status_code, "reference": str(account["bank_account_id"])}
