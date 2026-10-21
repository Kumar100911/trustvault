# THREATS.md

How I believe TrustVault could be broken, what I did, and what I knowingly accepted.
Status: DONE = fixed and tested, ACCEPTED = known weakness, PLANNED = will fix later.

## Authentication and sessions

| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 1 | Stolen database leaks working sessions | Only the SHA-256 fingerprint of the session token is stored | test_session_table_never_stores_the_raw_token | DONE |
| 2 | Session keeps working after account is disabled | is_active is re-checked in the database on every request | test_disabling_user_stops_existing_session_immediately | DONE |
| 3 | Learning which emails exist from login errors | Same 401 message and same timing for every failure | test_wrong_password_and_unknown_email_look_identical | DONE |
| 4 | Passwords stolen from the database | Argon2 hashes, never plain text | test_password_is_hashed_and_verifies | DONE |
| 5 | Forged or reused session cookie | Cookie is checked against the sessions table; logout deletes the row | test_forged_cookie_is_refused, test_logout_kills_the_session | DONE |
| 6 | Brute-force password guessing | No rate limit yet | none | PLANNED (Day 4) |
| 7 | CSRF | Relying on SameSite=Lax cookies only, no token | none | ACCEPTED for now, revisit Day 4 |

## Documents and access

| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 8 | Guessing document IDs (IDOR) | Random UUIDs; 404 for both "not yours" and "does not exist" | test_forbidden_and_nonexistent_look_identical | DONE |
| 9 | A stranger uses any document route | Every route loads documents through load_and_authorize, which calls authorize() | test_strangers_get_404_and_anonymous_gets_401 | DONE |
| 10 | Deleted documents stay reachable | authorize() refuses deleted documents, even for the owner | test_deleted_document_is_gone | DONE |
| 11 | Mass assignment (sending owner_id in an edit) | extra="forbid" on the update model | test_patch_rejects_unknown_fields | DONE |
| 12 | Document lists leak other people's titles | List query only returns owned or actively granted documents | test_list_shows_only_my_documents | DONE |
| 13 | Admin reads confidential contents | Admin role has no document rights by design | test_admin_cannot_read_contents | DONE |
| 14 | Viewer role uploads documents | Upload requires the owner role | test_viewer_role_cannot_upload | DONE |

## Uploads

| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 15 | Path traversal in filenames (../../etc/passwd) | Keep only the last path piece and safe characters; files have random keys and no file paths | test_filenames_are_sanitised | DONE |
| 16 | Fake file types (.exe renamed .pdf) | Extension allow-list plus magic-byte check | test_bad_uploads_are_rejected | DONE |
| 17 | HTML/SVG files running scripts in a browser | They are not allowed; downloads use attachment and nosniff | test_bad_uploads_are_rejected, test_owner_upload_download_roundtrip | DONE |
| 18 | Huge uploads | 10 MB limit, read in chunks | test_too_large_is_rejected | DONE |
| 19 | Renaming to a dangerous extension later | Rename cannot change the extension | test_rename_cannot_change_extension | DONE |
| 20 | Whole request body is received before the size check | A reverse-proxy size limit would fix it | none | ACCEPTED (free hosting, no proxy control) |
| 21 | Malware inside an allowed file type | No virus scanning | none | ACCEPTED (out of scope for one week) |

## Audit trail

| # | Threat | What I did | Test | Status |
|---|---|---|---|---|
| 22 | Someone edits an old audit row | Each row stores a hash that includes the previous row's hash; verify_chain recomputes all | test_audit_chain_detects_tampering | DONE |
| 23 | Fake log lines made with newlines in input | Control characters stripped from every logged value | covered by _clean | DONE |
| 24 | Two requests write at once and fork the chain | Postgres advisory lock in write_audit | none (needs a Postgres test) | ACCEPTED, untested |
| 25 | Denied attempts missing from the record | Denied document access is logged | test_denied_attempt_is_audited | DONE |
| 26 | Anonymous (401) attempts not logged | Not logged yet | none | PLANNED (Day 3) |
| 27 | Someone with database access deletes the newest rows | The chain alone cannot detect this | none | PLANNED (Day 3: DB trigger, saved head hash) |
| 28 | Client IP behind Render's proxy is the proxy's address | Spoofable headers are not trusted | none | ACCEPTED |

## Not built, on purpose

- Folder inheritance: it is how "access to one file" becomes "access to forty".
- Sharing with people outside the company: not enough time to do it safely.