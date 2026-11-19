# CR-26-047 | Tier 1 problem statement

**Team:** DEFENSE  
**Selected problem:** Can Harbor & Finch verify that an integration-made vendor bank change was both within the integration’s approved scope and independently authorized by Finance?

## What the records show

**11–12 Aug: confirmed unauthorized credential activity; disputed reach.** LedgerOne records successful calls from `key-tb-07` at E17 high-confidence indicator IPs. On 12 Aug, E01 `req-c35c2ccaff` created a vendor export returning 9,840 rows; `req-d877f18b6c` downloaded export 9931 (9,840 rows). `req-51b30fba51` created a second export returning 9,835 rows; `req-507360d11e` downloaded export 9932. Repeated payment searches returned 330 rows. E02 records the HelpDeskr integration creating, downloading, and deleting export jobs (for example, `evt-d5b7a8536`, `evt-3d5f15cc5c`, `evt-a0c8645bc`). E16 says the unauthorized activity was limited to ticket metadata and no finance records or stored files were accessed. The LedgerOne endpoints and successful row counts materially conflict with that account; the logs do not disclose the exported contents or identify the human operator. The API user-agent still says `TallyBridge-Sync/3.4.1`; a key and user-agent identify a credential/client, not a person.

**3 Sep: confirmed bank-detail write; authorization unresolved.** E18 request `req-5f61b0de8` shows `key-tb-07` successfully PATCHing V-0412 bank details at 01:44:30 UTC from `10.20.4.77`, with user-agent `TallyBridge-Sync/3.5.0`. E19 change `chg-8b9888c39b` matches the timestamp, request, source and masked account change (`****4417` to `****9083`); `approval_ref` is blank. The call follows a vendor/bank-details read and scheduled-payment query in E18. This proves a successful change, not who initiated it, whether it was approved outside the supplied log, or whether any payment was diverted.

## Competing explanations and gaps

The call falls inside the 01:30 UTC nightly-sync window (E20 release notes), and E18 shows ordinary contact updates in that run. E15 labels `10.20.4.77` as TallyBridge build host `tb-build-02` in earlier flows, making an integration path plausible. But E15 ends 31 Aug and cannot establish the 3 Sep route or host owner. E20 says release 3.6.0, from 1 Sep, syncs email and phone only; it does not explain a bank-account PATCH. These saved public records are unverified. An authorized exception, a misconfigured sync, a compromised integration path, and incomplete approval logging remain possible.

E04 is a 2 Sep current-state snapshot, not history: `key-tb-07` is active, all-modules read/write, unrestricted by IP, no expiry, last reviewed 12 Jun 2024. E10 requires narrow scope, expiry within 90 days, and IP restriction where supported; E11 reports open findings on unexpired/unrestricted keys and absent export/deletion alerts. E08 places configuration restrictions on the customer. This is a clear control failure even if the 3 Sep change proves legitimate.

## Defense approach and decision test

Build a bank-change authorization gate and reconciliation check: require a Finance approval reference before any bank-detail mutation; bind it to vendor, old/new value, request ID, key, source, endpoint/scope, and time; hold unmatched or conflicting changes for human review. Alerting only on unfamiliar public IPs may catch the August indicators but misses the private-link `10.20.4.77` write and cannot test authorization. Apply the seven checks to each call: key, expected source, client, endpoint/scope, expected window, records changed/returned, and matching record in the other system.

Resolve the case with the original Finance request/approval and payment records; LedgerOne key/scope/rotation history; and dated vendor build, tunnel, and deployment logs for 3 Sep. A linked approval plus corroborated authorized job would change the assessment. So would evidence the write caused a payment change. Until then, report the August access as unauthorized, the September bank change as confirmed but unapproved in the supplied record, and diversion as unproven. E01/E18/E19 are UTC; E02 is local time with no offset, so do not claim cross-system minute ordering.
