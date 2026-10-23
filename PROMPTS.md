# Prompts & AI Interaction History

## 2026-10-20 — Entry 1: Sessions (Day 1)
**Asked:** for a login system with sessions so that revoking access works instantly.
**Produced:** DB-backed sessions, with the cookie token hashed before it is stored.
**Checked:** I wrote `test_session_table_never_stores_the_raw_token` and `test_disabling_user_stops_existing_session_immediately`, then did a mutation check by removing the `is_active` check. The disabling test went red, so it really protects that rule.
**Wrong:** nothing found in this part. I am recording that I checked rather than assuming.
**Fixed:** n/a
**Commit:** [0acf316](https://github.com/kumar100911/trustvault/commit/0acf316)

## 2026-10-21 — Entry 2: CI failed on a clean machine (Day 1 to 2)
**Asked:** for the Day 1 steps including `pip freeze > requirements.txt` and git commits.
**Produced:** commit commands whose `git add` lists left out `requirements.txt`.
**Wrong:** GitHub Actions starts from a clean computer, so it could not find the `argon2` package and the build went red.
**Fixed:** read the Actions log, wrote `requirements.txt` by hand, added `pytest.ini`, committed. 
**Commit:** [3b3b0bb](https://github.com/kumar100911/trustvault/commit/3b3b0bb)

## 2026-10-21 — Entry 3: File storage design (Day 2)
**Asked:** how to store uploaded files safely.
**Produced:** an early plan to save files on disk outside the web folder.
**Wrong:** on free hosting the disk is wiped on every redeploy, so every document would vanish. It also needs file paths, which brings path-traversal risk.
**Fixed:** store file bytes in a separate Postgres table under a random key, saved in the same transaction as the document row. 
**Commit:** [2e27b93](https://github.com/kumar100911/trustvault/commit/2e27b93)

## 2026-10-21 — Entry 4: Refused attempts and the audit trail (Day 2)
**Asked:** for audit logging of uploads, downloads and denials.
**Produced:** a logged "denied" row for refused document access, but nothing for anonymous requests that are stopped by the login check (401).
**Wrong:** the brief says the record must include attempts that were refused. Anonymous attempts were missing, and the chain cannot detect deletion of the newest rows.
**Fixed:** listed both in `THREATS.md` (#26, #27) as PLANNED. Fix is Day 3. 
**Commit:** [602073d](https://github.com/kumar100911/trustvault/commit/602073d)

## 2026-10-22 — Entry 5: Revocation design (Day 3)
**Asked:** for a Day 3 plan covering grant and revoke.
**Produced:** a plan saying revoking a grant "also deletes any sessions or tokens tied to that access".
**Wrong:** sessions belong to the whole login, not to one document. Deleting them on every revoke would log people out of everything, and it protects nothing, because no per-document tokens exist. The real mechanism is that authorize() asks the database for an active grant on every request.
**Fixed:** revoke only sets revoked_at. Sessions are deleted only when an admin disables an account. Proved by test_revocation_takes_effect_on_the_very_next_request. 
**Commit:** [af03537](https://github.com/kumar100911/trustvault/commit/af03537)

## 2026-10-22 — Entry 6: Half-saved admin actions (Day 3)
**Asked:** for sessions code on Day 1, including revoke_all_sessions().
**Produced:** a helper that commits inside itself.
**Wrong:** if disabling an account used it, the account change, the session deletion and the audit row would be three separate commits, so a crash between them could leave an account disabled with no log row, or logged with sessions still alive.
**Fixed:** disable_user does the deletion inline so all three changes are one transaction. 
**Commit:** [af03537](https://github.com/kumar100911/trustvault/commit/af03537)

## 2026-10-21 — Entry 7: Permission changes and forbidden attempts auditing (Day 3)
**Asked:** to implement grant modification tracking and ensure forbidden/anonymous access attempts are properly recorded in the audit log.
**Produced:** specific tests (`test_permission_changes_are_audited` and `test_anonymous_and_forbidden_attempts_are_audited`) that verify exact sequences of grant changes and security blocks.
**Wrong:** initially, these tests failed because they expected the audit log to consist *only* of the document actions being tested, but background login attempts or session initializations were adding extra rows.
**Fixed:** updated the test queries to explicitly filter out login audit actions when performing exact sequence matches on document and grant operations.
**Commit:** [218dbd8](https://github.com/kumar100911/trustvault/commit/218dbd8)

## 2026-10-22 — Entry 8: Mutation checks for Day 3 access controls
**Asked:** to verify that all Day 3 access control and revocation tests were genuinely protecting their rules and not passing by coincidence.
**Produced:** a series of manual code mutations (such as removing the active grant check or altering revocation queries) to test test coverage.
**Wrong:** one mutation (altering the error message string) did not trigger any test failures, revealing that tests were asserting status codes rather than explicit error messages.
**Fixed:** sharpened assertions to check exact error states and verified that core security invariants turned their respective test suites red.
**Commit:** [af03537](https://github.com/kumar100911/trustvault/commit/af03537)

## 2026-10-23 — Entry 9: Duplicate __table_args__ (Day 3 code)
**Asked:** for the Day 3 grants index.
**Produced:** instructions to change the Grant class's `__table_args__`.
**Wrong:** the old `__table_args__` stayed lower in the class, so Python used the second one and the unique "one active grant" index vanished from the model. Every test still passed because none looked at the model itself.
**Fixed:** removed the duplicate and added `test_model_itself_forbids_two_active_grants` (checked by putting the duplicate back: the test goes red).
**Commit:** [73651f1](https://github.com/kumar100911/trustvault/commit/73651f1)

## 2026-10-23 — Entry 10: requirements.txt (Day 1 to 3)
**Asked:** for Day 1 steps including `pip freeze > requirements.txt`.
**Produced:** a command that in Windows PowerShell writes UTF-16, and a freeze that did not include `python-multipart`.
**Wrong:** on a clean Linux machine the app crashes on import ("Form data requires python-multipart"). It passed on my laptop only because the package was installed there.
**Fixed:** saved it as UTF-8 with the package added. Verified in a brand-new virtual environment.
**Commit:** [646500c](https://github.com/kumar100911/trustvault/commit/646500c)

## 2026-10-23 — Entry 11: Tests tied to exact audit rows (Day 4)
**Asked:** for login auditing on top of Day 3.
**Produced:** a design that writes a "login" row for every attempt.
**Wrong:** three Day 3 tests compared the whole audit log to an exact list, so they failed on the new rows. The guard test also refused the three new suggestion routes until they were put in the access matrix (it worked as designed).
**Fixed:** those three tests now ignore "login" rows (they are about document actions), and the matrix covers the suggestion routes.
**Commit:** [7b8f354](https://github.com/kumar100911/trustvault/commit/7b8f354)