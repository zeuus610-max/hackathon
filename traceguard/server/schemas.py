"""Validated request models for the defensive simulation API."""

from typing import Literal
from datetime import datetime
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str | None = Field(default=None, max_length=120)
    key_id: str = Field(min_length=1, max_length=120)
    system: str = Field(default="LedgerOne", max_length=80)
    endpoint: str = Field(default="", max_length=240)
    user_agent: str = Field(default="", max_length=240)
    caller_ip: str | None = Field(default=None, max_length=64)
    timestamp: str | None = Field(default=None, max_length=64)
    sync_window: Literal["expected", "outside", "unknown"] = "expected"
    request_volume: int = Field(default=1, ge=0, le=1_000_000)
    export_volume: int = Field(default=0, ge=0, le=1_000_000)
    e02_receipt: Literal["present", "missing", "unknown"] = "unknown"
    e15_receipt: Literal["present", "missing", "unknown"] = "unknown"
    action_sequence: list[str] = Field(default_factory=list, max_length=30)
    request_id: str | None = Field(default=None, max_length=120)

    @field_validator("action_sequence")
    @classmethod
    def validate_action_lengths(cls, value):
        if any(len(action) > 100 for action in value):
            raise ValueError("Each action must be 100 characters or fewer")
        return value

    @field_validator("caller_ip")
    @classmethod
    def validate_ip(cls, value):
        if value:
            ip_address(value)
        return value

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, value):
        if value:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("Timestamp must include an explicit timezone")
        return value


class ValidationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    true_positives: int = Field(ge=0, le=1_000_000)
    false_positives: int = Field(ge=0, le=1_000_000)
    missed_detections: int = Field(ge=0, le=1_000_000)
    evidence_row_ids: list[str] = Field(default_factory=list, max_length=100)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)

    @field_validator("evidence_row_ids")
    @classmethod
    def validate_ids(cls, value):
        if any(len(item) > 120 for item in value):
            raise ValueError("Evidence row IDs must be 120 characters or fewer")
        return value


class EvidenceReferencesUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    references: dict[str, str] = Field(max_length=9)

    @field_validator("references")
    @classmethod
    def validate_references(cls, value):
        allowed = {"E01", "E02", "E03", "E04", "E05", "E15", "E17", "E18", "E19"}
        if set(value) - allowed or any(len(ref) > 120 for ref in value.values()):
            raise ValueError("Use known evidence IDs and references up to 120 characters")
        return value


class ChecklistUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(min_length=1, max_length=80)
    checked: bool


class EvidenceHashRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    evidence_id: str = Field(min_length=1, max_length=20, pattern=r"^E\d{2}$")


class BankDetails(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    bank_name: str = Field(min_length=2, max_length=120)
    account_holder: str = Field(min_length=2, max_length=120)
    account_number: str = Field(min_length=4, max_length=34, pattern=r"^[A-Za-z0-9 -]+$")
    routing_code: str = Field(min_length=4, max_length=34, pattern=r"^[A-Za-z0-9 -]+$")
    country: str = Field(min_length=2, max_length=2, pattern=r"^[A-Za-z]{2}$")


class VendorBankChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: str = Field(min_length=8, max_length=120, pattern=r"^[A-Za-z0-9._:-]+$")
    idempotency_key: str = Field(min_length=16, max_length=120, pattern=r"^[A-Za-z0-9._:-]+$")
    vendor_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._:-]+$")
    bank_details: BankDetails


class VendorBankChangeApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    bank_details: BankDetails
    confirm_exact_details: bool
