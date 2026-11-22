# High-Level Design & Threat Model — Kryptos-C

## 1. File Storage Specification (`kryptos_vault.dat`)
Line 1 stores the authenticated vault header:
`KRYPTOS_HDR|<random_salt>|<djb2_pin_hash>|<fnv1a_checksum>`

Subsequent lines store encrypted credential records:
`<id>|<service>|<username>|<encrypted_password>|<strength_score>`

## 2. Threat Model & Mitigations
| Threat | Mitigation Implemented |
| :--- | :--- |
| Plaintext credential exposure on disk | Salted symmetric stream encryption prior to file write |
| Unauthorized CLI access | Salted DJB2 Master PIN verification + 3-attempt lockout |
| External file modification/corruption | FNV-1a integrity checksum verified on startup |
| Memory scraping / residual secrets | `volatile` RAM scrubbing (`secureWipe`) on exit/delete |
| Password reuse & weak credentials | Automated strength scoring + duplicate detection audit |