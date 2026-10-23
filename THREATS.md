# TrustVault Threat Model & Mitigations

This document outlines the security threats identified during the design and implementation of TrustVault, along with the concrete technical defenses and verification tests implemented for each.

---

## Days 1–2: Foundations, Authentication & File Storage

| # | Threat | What I did | Test | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Unauthorized file reading | Centralized default-deny `authorize()` gatekeeper on every route | `test_unauthorized_user_cannot_read` | DONE |
| **2** | Resource enumeration via 403 Forbidden | Return `404 Not Found` instead of `403 Forbidden` for inaccessible resources | `test_unauthorized_returns_404` | DONE |
| **3** | Session hijacking via cookie theft | Cookie tokens are cryptographically hashed before saving in the database; raw tokens never touch storage | `test_session_table_never_stores_the_raw_token` | DONE |
| **4** | Revocation delay | Database queried on every request via `authorize()` so token revocation takes effect instantly | `test_revocation_takes_effect_on_the_very_next_request` | DONE |
| **5** | Disk wiped on cloud redeploys | File binaries stored in a dedicated Postgres blob table mapped by random UUID keys | `test_file_bytes_stored_in_db_table` | DONE |
| **6** | Path-traversal file attacks | Filenames sanitized and file bytes stored via content-addressable storage keys rather than direct disk paths | `test_filename_sanitization` | DONE |
| **7** | Malicious file uploads (e.g., executable scripts) | Strict allow-list extension check combined with magic-byte verification | `test_upload_validation_magic_bytes` | DONE |
| **8** | Audit log tampering | Hash-chained audit entries where each row's hash depends on the preceding row (`verify_chain()`) | `test_audit_chain_verification` | DONE |
| **9** | Audit log deletion/alteration | Database trigger blocks `UPDATE`, `DELETE`, and `TRUNCATE` operations on the audit log table | `test_audit_trigger_blocks_updates` | DONE |

---

## Day 3: Sharing, Revocation & Role Matrices

| # | Threat | What I did | Test | Status |
| :--- | :--- | :--- | :--- | :--- |
| **10** | Multiple active grants conflict | Unique partial database index restricts a user to exactly one active grant per document | `test_model_itself_forbids_two_active_grants` | DONE |
| **11** | Unaudited privilege escalation | All permission grants, changes, and revocations logged with actor and timestamp | `test_permission_changes_are_audited` | DONE |
| **12** | Anonymous or forbidden actions missing from audit | Centralized `refuse()` logs both 401 and 403 security blocks | `test_anonymous_and_forbidden_attempts_are_audited` | DONE |
| **13** | Privilege drift across roles | Comprehensive route-by-role test matrix validation (`test_matrix.py`) | `test_every_route_for_every_kind_of_person` | DONE |
| **14** | Admin account takeover / unauthorized admin actions | Strict `require_admin` dependency gate on administrative endpoints | `test_admin_routes_forbidden_for_non_admins` | DONE |

---

## Day 4: Search, Login Protection, Admin Alerts & AI Suggestions

| # | Threat | What I did | Test | Status |
| :--- | :--- | :--- | :--- | :--- |
| **44** | Search leaks titles, counts or unreadable documents | Search starts from `visible_documents()`; filters only narrow authorized results | `test_search_never_returns_what_you_cannot_read`, `test_search_agrees_with_authorize_for_every_user_and_filter` | DONE |
| **45** | `%` and `_` used as wildcards to dump database records | Escaped to ordinary SQL characters | `test_search_wildcards_are_plain_characters` | DONE |
| **46** | Owner-email filter used to enumerate system users | Only applies inside documents the caller can already read | `test_search_never_returns_what_you_cannot_read` | DONE |
| **47** | Password brute force attacks | 5 failures per email per 15-minute window triggers a `429` lockout, checked *before* password verification | `test_repeated_failures_lock_the_account_even_for_the_right_password` | DONE |
| **48** | Attacker intentionally locks a real user out | Lock expires automatically after 15 minutes; flagged in admin alerts | `test_old_failures_stop_counting_after_the_window` | ACCEPTED |
| **49** | Password spraying from one IP over many emails | No per-IP rate limit applied (Render proxy pools all users behind a single shared IP) | none | ACCEPTED |
| **50** | Logins invisible in the security record | Every success, failure, and lockout audited; passwords are never logged | `test_login_attempts_are_audited` | DONE |
| **51** | AI suggestion widens access automatically | Suggestion endpoint only reads; confirmation requires a separate human request restricted to named candidates | `test_suggestion_ranks_people_and_grants_nothing`, `test_cannot_confirm_someone_the_suggestion_did_not_name`, `test_suggest_module_cannot_write_grants` | DONE |
| **52** | Suggestion reused on another document or by another person | Validates document ID and creator binding; misuse is explicitly audited | `test_suggestions_cannot_be_used_by_other_people_or_on_other_documents` | DONE |
| **53** | AI model exposes file contents | Rule-based metadata analysis only; never touches file contents or external LLMs | `test_suggest_module_cannot_write_grants` | DONE |
| **54** | Grants made to outside email domains go unnoticed | Admin security alert flags grants where the recipient domain differs from the giver's domain | `test_alerts_flag_grants_to_outside_email_domains` | DONE |
| **55** | Weak passwords on admin-created accounts | Enforces minimum 12-character length requirement | `test_user_creation_is_validated` | DONE (Partly) |
| **56** | Same email registered in different letter cases | Email normalized to lowercase before saving or looking up | `test_duplicate_email_is_refused_even_with_different_case` | DONE |
| **57** | Security alerts evaded via low-volume probes | Threshold rules kept simple and explainable for security audits | none | ACCEPTED |
| **58** | Duplicate `__table_args__` silently drops unique active-grant index | Removed duplicate block and added explicit model regression test | `test_model_itself_forbids_two_active_grants` | DONE |
| **59** | `requirements.txt` lacks dependency causing clean-install crash | Saved as clean UTF-8 including `python-multipart` | CI clean install verification | DONE |