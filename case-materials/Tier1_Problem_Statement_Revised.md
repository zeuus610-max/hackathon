# CR-26-047 | Tier 1 problem statement

**Team:** DEFENSE  
**Finding:** A TallyBridge integration credential made 71 recorded vendor updates from 1–7 Sep. E18 and E19 match all 71 by request ID: 70 changed vendor email or phone; one changed a bank account. The bank change has no Finance approval reference in E19 and falls outside the sync’s stated purpose.

**Problem chosen:** Can Harbor & Finch prove each integration-made bank change was authorized by Finance and within the integration’s approved scope?

## The one change that does not fit

On 3 Sep at 01:44:30 UTC, E18 request `req-5f61b0de8` successfully PATCHed V-0412 bank details using `key-tb-07` from `10.20.4.77` with user-agent `TallyBridge-Sync/3.5.0`. E19 change `chg-8b9888c39b` matches the request ID, source and time; the masked account changed from `****4417` to `****9083`, and `approval_ref` is blank. E16 says the new 1 Sep sync updates vendor email and phone. The change is five days before the usual 8 Sep vendor payment run (case file); the records do not show whether V-0412 was due or whether any payment was diverted.

## What could explain it

This request ran inside the 01:30 UTC nightly-sync window and alongside ordinary contact updates. E15 labels `10.20.4.77` as TallyBridge build host `tb-build-02` in earlier flows, so an integration route is plausible. But E15 ends 31 Aug and cannot verify the 3 Sep source or host owner. E20’s saved release notes describe contact-only sync, not bank changes; those public records are unverified. An approved exception missing from E19, a misconfigured sync, a compromised integration path, or incomplete approval logging remain possible. The evidence does not link the August operator to the September write.

## Separate August concern

E16 says unauthorized credential requests occurred on 11–12 Aug. E01 records successful LedgerOne vendor exports and payment searches under `key-tb-07` from IPs E17 lists as high-confidence unauthorized indicators. This supports concern that the activity reached beyond HelpDeskr tickets, but the logs do not show exported contents or identify the human operator. E02 also records HelpDeskr export jobs created, downloaded and deleted. Its timestamps are local with no offset, so do not assert minute-by-minute ordering across systems.

## Control gap and defense approach

E04 is a 2 Sep snapshot, not history: `key-tb-07` is active, all-modules read/write, has no IP restriction or expiry, and was last reviewed 12 Jun 2024. E10 requires minimum scope, expiry within 90 days and IP restrictions where supported; E11 reports related open findings. E08 makes Harbor & Finch responsible for configuring restrictions. This control gap exists even if the 3 Sep change was approved.

Build a scope-aware bank-change control: for every API change, join the request to the vendor record and Finance approval; compare the field changed with the integration’s allowed fields. Require approval before bank changes and hold mismatches for human review. Check key, source, client, scope, timing, amount changed and matching record. An unfamiliar-public-IP alert may catch the August indicators but would miss an internal private-link request and cannot prove Finance approval.

**What would change the assessment:** the original Finance approval and payment records; LedgerOne key/scope/rotation history; and dated vendor build, tunnel and deployment logs for 3 Sep. A linked approval plus corroborated authorized job would support legitimacy; evidence of a changed payment would raise impact. Until then, the bank write is confirmed, authorization is unresolved, and diversion is unproven. E01/E18/E19 use UTC; E02 is local time with no offset.
