## Reusable instructions I gave the AI
- "Act as a trainer for a beginner who knows Python and LeetCode but not Git or web security. One step at a time, with a checkpoint after each."
- "Every document route must go through one authorize() function. Default deny. Return 404, not 403."
- "Never trust the filename or the content type from the browser."

---

## 2026-10-20 — Entry 1: Sessions (Day 1)
**Asked:** for a login system with sessions so that revoking access works instantly.
**Produced:** DB-backed sessions, with the cookie token hashed before it is stored.
**Checked:** I wrote `test_session_table_never_stores_the_raw_token` and `test_disabling_user_stops_existing_session_immediately`, then did a mutation check by removing the `is_active` check. The disabling test went red, so it really protects that rule.
**Wrong:** nothing found in this part. I am recording that I checked rather than assuming.
**Fixed:** n/a
**Commit:** [cf9e073](https://github.com/kumar100911/trustvault/commit/cf9e073)

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