"""QuickBooks Online sandbox adapter for Orbit's approved vendor changes."""

from __future__ import annotations

import asyncio
import json
import os
from urllib.parse import quote

import httpx
from cryptography.fernet import Fernet, InvalidToken


SANDBOX_API = "https://sandbox-quickbooks.api.intuit.com/v3/company"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
_refresh_lock = asyncio.Lock()


class QBOError(Exception):
    """Safe, non-secret error suitable for an audit event."""


def _cipher() -> Fernet:
    try:
        return Fernet(os.environ["ORBIT_DATA_ENCRYPTION_KEY"].encode("ascii"))
    except (KeyError, ValueError, UnicodeEncodeError) as exc:
        raise QBOError("Orbit encryption is not configured") from exc


async def _access_token(client: httpx.AsyncClient, *, realm_id: str,
                        client_id: str, client_secret: str,
                        initial_refresh_token: str, store) -> str:
    """Refresh OAuth credentials and persist Intuit's rotated token encrypted."""
    async with _refresh_lock:
        meta_key = f"qbo_refresh_token:{realm_id}"
        encrypted = store.get_meta(meta_key)
        if encrypted:
            try:
                refresh_token = _cipher().decrypt(encrypted.encode()).decode()
            except (InvalidToken, UnicodeDecodeError) as exc:
                raise QBOError("Stored QuickBooks refresh token cannot be decrypted") from exc
        else:
            refresh_token = initial_refresh_token
        try:
            response = await client.post(
                TOKEN_URL,
                auth=(client_id, client_secret),
                data={"grant_type": "refresh_token", "refresh_token": refresh_token},
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise QBOError("QuickBooks OAuth refresh failed") from exc
        if response.status_code != 200:
            raise QBOError(f"QuickBooks OAuth refresh returned HTTP {response.status_code}")
        try:
            tokens = response.json()
            access_token = tokens["access_token"]
            rotated_token = tokens.get("refresh_token", refresh_token)
            if not isinstance(access_token, str) or not access_token:
                raise ValueError("Missing access token")
            if not isinstance(rotated_token, str) or not rotated_token:
                raise ValueError("Missing refresh token")
        except (ValueError, KeyError, TypeError) as exc:
            raise QBOError("QuickBooks OAuth response was invalid") from exc
        store.set_meta(meta_key, _cipher().encrypt(rotated_token.encode()).decode())
        return access_token


async def apply_vendor_bank_details(*, realm_id: str, client_id: str,
                                    client_secret: str, initial_refresh_token: str,
                                    vendor_id: str, bank_details: dict, store) -> dict:
    """Sparse-update only QBO vendor bank fields in the fixed sandbox API.

    QBO's VendorPaymentBankDetail has no institution-name field. Orbit maps the
    approved account holder to BankAccountName and the routing code to
    BankBranchIdentifier; bank_name is retained in Orbit's approval record but
    is not sent to QBO. QBO's SyncToken prevents overwriting a newer vendor row.
    """
    if not all((realm_id, client_id, client_secret, initial_refresh_token, vendor_id)):
        raise QBOError("QuickBooks sandbox OAuth configuration is incomplete")
    base = f"{SANDBOX_API}/{quote(realm_id, safe='')}/vendor"
    vendor_url = f"{base}/{quote(vendor_id, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=4.0)) as client:
            token = await _access_token(
                client, realm_id=realm_id, client_id=client_id,
                client_secret=client_secret, initial_refresh_token=initial_refresh_token,
                store=store)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            current = await client.get(vendor_url, headers=headers)
            if current.status_code != 200:
                raise QBOError(f"QuickBooks vendor read returned HTTP {current.status_code}")
            try:
                vendor = current.json()["Vendor"]
                sync_token = vendor["SyncToken"]
                resolved_id = str(vendor["Id"])
            except (ValueError, KeyError, TypeError) as exc:
                raise QBOError("QuickBooks vendor response was missing its version") from exc
            body = {
                "Id": resolved_id,
                "SyncToken": str(sync_token),
                "sparse": True,
                "VendorPaymentBankDetail": {
                    "BankAccountName": bank_details["account_holder"],
                    "BankBranchIdentifier": bank_details["routing_code"],
                    "BankAccountNumber": bank_details["account_number"],
                },
            }
            updated = await client.post(
                base, params={"operation": "update"}, headers=headers, json=body)
            if not 200 <= updated.status_code < 300:
                raise QBOError(f"QuickBooks vendor update returned HTTP {updated.status_code}")
            try:
                response_vendor = updated.json().get("Vendor", {})
                if str(response_vendor.get("Id", "")) != resolved_id:
                    raise QBOError("QuickBooks update response did not confirm the target vendor")
            except (ValueError, AttributeError) as exc:
                raise QBOError("QuickBooks update response was invalid") from exc
            return {"status_code": updated.status_code,
                    "intuit_tid": updated.headers.get("intuit_tid")}
    except httpx.HTTPError as exc:
        raise QBOError("QuickBooks sandbox request failed") from exc
