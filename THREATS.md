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
| 24 | Two requests write at once and fork the chain | Postgres advisory lock in write_audit | test_concurrent_writers_keep_the_chain_valid | DONE (tested in CI) |
| 25 | Denied attempts missing from the record | Denied document access is logged | test_denied_attempt_is_audited | DONE |
| 26 | Anonymous (401) attempts not logged | Logged via refuse() helper | test_anonymous_and_forbidden_attempts_are_audited | DONE |
| 27 | Someone with database access deletes the newest rows | Saved head fingerprint in ANCHORS.md; verify checks it | test_saved_fingerprint_detects_deleted_newest_rows | DONE |
| 28 | Client IP behind Render's proxy is the proxy's address | Spoofable headers are not trusted | none | ACCEPTED |
| 29 | Revoking a grant through a different document’s URL | Grant must belong to the document in the URL | test_cannot_revoke_a_grant_through_a_different_document | DONE |
| 30 | An editor or reader shares the document further | Sharing is the owner-only manage action | matrix: editor/reader → create_grant | DONE |
| 31 | Revoked user keeps access | DB checked every request; no per-document links or tokens exist | test_revocation_takes_effect_on_the_very_next_request | DONE |
| 32 | Download already in progress when revoked | File is sent as one response, so it may complete | none | ACCEPTED |
| 33 | Two active grants from a race | Partial unique index; API returns 409 | test_two_active_grants_for_one_person_are_impossible | DONE |
| 34 | Audit rows altered or deleted by a bug or injected SQL | DB trigger refuses UPDATE, DELETE, TRUNCATE | test_audit_rows_cannot_be_changed_deleted_or_truncated | DONE |
| 35 | Newest audit rows deleted | Saved head fingerprint in ANCHORS.md; verify checks it | test_saved_fingerprint_detects_deleted_newest_rows | DONE, needs me to keep anchoring |
| 36 | App connects as the DB owner, who can drop the trigger | Not fixed (a separate INSERT-only role would fix it) | none | ACCEPTED |
| 37 | Disabled user keeps a session | Sessions deleted and is_active checked every request | test_disabling_a_user_cuts_their_session_at_once | DONE |
| 38 | Last admin locked out | Admin cannot disable self | test_admin_cannot_disable_themselves_or_missing_users | DONE |
| 39 | Non-admin reaches admin routes | require_admin, with refusals logged | test_only_admins_reach_admin_routes | DONE |
| 40 | Owner discovers which emails exist (“No such user”) | Not fixed | none | ACCEPTED |
| 41 | Re-enabled user gets old grants back | By design, and grants can be revoked first | none | ACCEPTED |
| 42 | Anonymous requests flood the audit table | Not fixed yet | none | PLANNED (Day 4 rate limiting) |
| 43 | A new route forgets the authorisation matrix | Test fails if a {doc_id} route is missing from the matrix | test_every_document_route_is_in_the_matrix | DONE |

## Not built, on purpose
- Folder inheritance: it is how "access to one file" becomes "access to forty".
- Sharing with people outside the company: not enough time to do it safely.