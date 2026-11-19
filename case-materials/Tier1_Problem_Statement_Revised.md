# CRIMEATHON ’26 | Case CR-26-047

## A vendor bank change without a verifiable approval trail

**Tier 1 / Problem statement / Draft for team review**<br>**Defense | Existing draft selection**

On 3 Sep, the TallyBridge LedgerOne key successfully changed Coastal Packaging’s bank details. The matching Finance change record has no approval reference. The evidence confirms the write; it does not establish who initiated it, whether it was authorized, or whether any payment was diverted.

### The record-level join

**E18 | API request** — 03 Sep 2026 01:44:30 UTC; `req-5f61b0de8`; HTTP 200; `PATCH /v2/vendors/V-0412/bank-details`; `key-tb-07`; `10.20.4.77`.

**E19 | Change record** — `chg-8b9888c39b`; API; `bank_account ****4417 → ****9083`; `approval_ref: blank`.

Same request ID, time, vendor, and source IP.

**71** E18/E19 request-ID matches from Sep 1–7. **70** contact changes: 44 phone and 26 email. **1** bank-account change: a different field.

### What the records support

The same key and source read V-0412 (`req-15a052a5e`), its bank details (`req-93d66fcd5`), then `/v2/payments/scheduled` (`req-33a3928eca`) before the PATCH. The endpoint returned 14 records; the log does not show whether V-0412 was among them. No payment outcome is supplied.

E16/E20 announce email and phone contact sync from 1 Sep. The 70 matched contact changes fit that description; the `bank_account` change differs from the announced field list. E18 reports user-agent 3.5.0 although E20 lists release 3.6.0 on 1 Sep; the user-agent alone does not prove deployed code.

E04 shows `key-tb-07` with all-modules read/write, no IP restriction or expiry, and a last review in 2024. E10 requires least scope, expiry within 90 days and IP restriction where supported. E11 records relevant audit findings open in Sep 2025; the planned 2026 follow-up status is absent.

### Limits and alternatives

A blank `approval_ref` is not proof of no approval: E19 has three other bank changes with blank references, all through the UI. The 2024 onboarding request also includes vendors and payments (E07), so the evidence does not establish that this write violated the full original approval.

The write occurred five days before the usual 8 Sep payment run, but no record shows whether V-0412 was included or paid. E15 labels `10.20.4.77` as `tb-build-02`, but the label is unverified and its flow log ends 31 Aug.

August export activity in E01/E02 conflicts with E16’s metadata-only account; E02 also records a delete timeout. Public IPs are dynamic and the indicators are vendor-supplied. The exposed BlueVault key and post-exit Rohan sign-in are separate leads, with no evidence tying either to this bank change.

Normal Tuesday support exports, the 31 Jul Finance bulk import (E19, `BULK-0731`), and the announced contact sync explain other activity, not this Sep 3 bank-field PATCH.

### Problem selected | Defense

Build a review checker that joins each integration bank change to its API request, compares the changed field with the documented sync purpose, and requires an independent Finance approval record. Missing or conflicting evidence goes to a human reviewer; the tool must not label a blank field as fraud.

### Why not IP-only | What would change the view

An unfamiliar-IP alert could flag the August public addresses but would miss a private-network write and would not test field scope or approval. A verified Finance request for V-0412, authoritative connector/host history, or the 8 Sep payment reconciliation could change this assessment.

**Approach status:** Defense is the existing draft selection. Team agreement and Tier 1 submission status are unverified; confirm before treating the choice as final or locked. **Time basis:** E18/E19/E01/E03/E15 are UTC; E02 is tenant-local with no offset; E05 clock is unsynchronized.
