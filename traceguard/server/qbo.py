"""QuickBooks Online sandbox adapter for Orbit's approved vendor changes."""

from __future__ import annotations

import asyncio
import json
import os
import re
from urllib.parse import quote

import httpx
from cryptography.fernet import Fernet, InvalidToken


SANDBOX_API = "https://sandbox-quickbooks.api.intuit.com/v3/company"
QBO_MINOR_VERSION = "75"
TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
_refresh_lock = asyncio.Lock()


class QBOError(Exception):
    """Safe, non-secret error suitable for an audit event."""


def _qbo_vendor_id(orbit_vendor_id: str) -> str:
    """Resolve a case/vendor ID to its QBO sandbox Vendor ID when configured."""
    raw = os.getenv("ORBIT_QBO_VENDOR_ID_MAP_JSON", "")
    if not raw:
        return orbit_vendor_id
    try:
        mapping = json.loads(raw)
        if (not isinstance(mapping, dict)
                or not all(isinstance(k, str) and isinstance(v, str) and v
                           for k, v in mapping.items())):
            raise ValueError("Expected string vendor ID mapping")
    except (ValueError, json.JSONDecodeError) as exc:
        raise QBOError("QuickBooks vendor ID mapping is invalid") from exc
    return mapping.get(orbit_vendor_id, orbit_vendor_id)


def _bank_fields_confirmed(vendor: dict, bank_details: dict) -> bool:
    fields = vendor.get("VendorPaymentBankDetail")
    if not isinstance(fields, dict):
        return False
    account_number = str(fields.get("BankAccountNumber") or "")
    routing_code = re.sub(r"[\s-]", "", str(fields.get("BankBranchIdentifier") or ""))
    return (
        fields.get("BankAccountName") == bank_details["account_holder"]
        and routing_code == re.sub(r"[\s-]", "", bank_details["routing_code"])
        and len(account_number) >= 4
        and account_number[-4:] == bank_details["account_number"][-4:]
    )


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
    """Update QBO vendor bank fields in the fixed sandbox API.

    QBO's Vendor update operation is a full update. Preserve the current vendor
    record and replace only the approved bank fields in the submitted object.
    VendorPaymentBankDetail has no institution-name field, so bank_name remains
    in Orbit's encrypted approval record. QBO's SyncToken prevents overwriting
    a newer vendor row.
    """
    if not all((realm_id, client_id, client_secret, initial_refresh_token, vendor_id)):
        raise QBOError("QuickBooks sandbox OAuth configuration is incomplete")
    vendor_id = _qbo_vendor_id(vendor_id)
    base = f"{SANDBOX_API}/{quote(realm_id, safe='')}/vendor"
    vendor_url = f"{base}/{quote(vendor_id, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0, connect=4.0)) as client:
            token = await _access_token(
                client, realm_id=realm_id, client_id=client_id,
                client_secret=client_secret, initial_refresh_token=initial_refresh_token,
                store=store)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            current = await client.get(
                vendor_url, params={"minorversion": QBO_MINOR_VERSION}, headers=headers)
            if current.status_code != 200:
                raise QBOError(f"QuickBooks vendor read returned HTTP {current.status_code}")
            try:
                vendor = current.json()["Vendor"]
                sync_token = vendor["SyncToken"]
                resolved_id = str(vendor["Id"])
            except (ValueError, KeyError, TypeError) as exc:
                raise QBOError("QuickBooks vendor response was missing its version") from exc
            body = dict(vendor)
            routing_code = bank_details["routing_code"]
            if re.fullmatch(r"\d{6}", routing_code):
                routing_code = f"{routing_code[:3]}-{routing_code[3:]}"
            body.update({
                "Id": resolved_id,
                "SyncToken": str(sync_token),
                "VendorPaymentBankDetail": {
                    "BankAccountName": bank_details["account_holder"],
                    "BankBranchIdentifier": routing_code,
                    "BankAccountNumber": bank_details["account_number"],
                    "StatementText": bank_details.get("statement_text", ""),
                },
            })
            updated = await client.post(
                base,
                params={"operation": "update", "minorversion": QBO_MINOR_VERSION},
                headers=headers, json=body)
            if not 200 <= updated.status_code < 300:
                raise QBOError(f"QuickBooks vendor update returned HTTP {updated.status_code}")
            try:
                response_vendor = updated.json().get("Vendor", {})
                if str(response_vendor.get("Id", "")) != resolved_id:
                    raise QBOError("QuickBooks update response did not confirm the target vendor")
            except (ValueError, AttributeError) as exc:
                raise QBOError("QuickBooks update response was invalid") from exc
            confirmed = _bank_fields_confirmed(response_vendor, bank_details)
            if not confirmed:
                verified = await client.get(
                    vendor_url, params={"minorversion": QBO_MINOR_VERSION}, headers=headers)
                if verified.status_code != 200:
                    raise QBOError(f"QuickBooks vendor readback returned HTTP {verified.status_code}")
                try:
                    persisted = verified.json()["Vendor"]
                except (ValueError, KeyError, TypeError) as exc:
                    raise QBOError("QuickBooks vendor readback was invalid") from exc
                confirmed = _bank_fields_confirmed(persisted, bank_details)
            if not confirmed:
                raise QBOError("QuickBooks did not confirm the approved vendor bank details")
            return {"status_code": updated.status_code,
                    "intuit_tid": updated.headers.get("intuit_tid")}
    except httpx.HTTPError as exc:
        raise QBOError("QuickBooks sandbox request failed") from exc
