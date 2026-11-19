# CRIMEATHON ’26 | Case CR-26-047

## 71 matched API PATCHes. One bank-field change.

**Sep 1–7, 2026 | E18 request IDs matched to E19 | Approach: DEFENSE**

On 3 Sep, `key-tb-07` successfully PATCHed Coastal Packaging’s (V-0412) bank details. E18 and E19 match the request; E19 records `****4417 → ****9083` and a blank `approval_ref`. The write is confirmed. The operator is unknown, authorization is unresolved, and payment diversion is not established.

### The record-level join

**E18 | API request** — `req-5f61b0de8`; 03 Sep 2026 01:44:30 UTC; HTTP 200; `PATCH /v2/vendors/V-0412/bank-details`; `key-tb-07`; `10.20.4.77`.

**E19 | Change record** — `chg-8b9888c39b`; API; same request ID, vendor, time, and source.

**71** successful API PATCHes match by request ID across Sep 1–7. **70** updated contact fields (44 phone, 26 email). **1** changed a bank-account field.

The 70 contact updates fit E16/E20’s announced email/phone sync. The bank-field change does not fit that announced 2026 sync purpose. But E07’s 2024 onboarding approval included vendors and payments, so the record does **not** establish that the change fell outside the full original approval.

### What fits / what does not

**Fits a sync path:** The nightly job was announced to start at 01:30 UTC; the write occurred at 01:44:30. All 11 successful Sep 3 PATCHes under this key used `TallyBridge-Sync/3.5.0`: 10 contact updates and this bank update. E20 lists release 3.6.0, while E18’s user-agent says 3.5.0; the user-agent does not establish deployed code. E15 labels `10.20.4.77` as `tb-build-02` in earlier flows. That label is unverified; E15 ends 31 Aug.

**Needs explanation:** The sync announcement names email and phone, not bank details. Before the write, E18 records reads of V-0412 and its bank details, then a scheduled-payment query returning 14 rows. The log does not show whether V-0412 was among them or any payment outcome. The evidence cannot distinguish a previously approved change, a legacy/misconfigured sync, a compromised integration path, or incomplete approval logging.

### Approval and control context

E19 contains 40 bank-change records: 27 UI changes (24 with approval references, 3 blank), 12 imports (all with references), and this sole API bank change, with a blank reference. A blank field is not proof that approval did not exist; the API baseline is only one event. E04 is a 2 Sep snapshot: `key-tb-07` had all-modules read/write access, no IP restriction or expiry, and last review in 2024. E10 calls for least scope, expiry within 90 days, and IP limits where supported; E11’s related findings were open, with 2026 follow-up status absent. E08 assigns configuration limits to Harbor & Finch.

### Separate August lead | E01/E02/E16/E17

On 12 Aug UTC, E01 records successful LedgerOne vendor exports returning 9,840 and 9,835 rows, plus 330-row payment-search responses. E02 records 10 HelpDeskr export jobs across tenant-local 11–12 Aug: nine deletes succeeded and one timed out. This conflicts with E16’s “ticket metadata only” account, but the logs do not show exported contents or identify the operator. E17’s indicators are vendor-supplied; E20 says public IPs can be reassigned. No evidence links the August activity to the Sep 3 write.

### Selected problem | Defense

Finance cannot verify from its own records that an integration-made bank change matches the documented sync purpose and has a linked Finance approval. Build a field-aware control: require a verifiable approval for bank-field changes and hold missing or conflicting links for review. If the platform cannot block the write, reconcile and escalate it promptly. Never label a blank reference as fraud.

**Our read:** high confidence that the bank-field write was recorded; low confidence about operator, approval, and payment impact. This is an authorization-verification gap, not proven theft. The assessment could change with the original Finance request, approval-system audit, deployed connector/configuration history, and V-0412’s Sep 8 payment reconciliation (case file: vendor runs on the 8th and 23rd; inclusion/payment are not shown).

**Clock basis:** E01/E03/E15/E18/E19 are UTC; E02 is tenant-local with no offset; E05 clock is unsynchronized.
