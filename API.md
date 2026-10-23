# TrustVault API & Access Matrix

This document defines the complete route-by-route permission matrix for TrustVault. Every endpoint is guarded by the centralized default-deny `authorize()` or role-based dependency checks (`require_user`, `require_admin`).

---

## Permission Matrix

| Method & Route | Anonymous | Viewer | Ungranted Viewer | Owner | Admin | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`POST /auth/login`** | Yes | Yes | Yes | Yes | Yes | Authenticates credentials; logs attempts; triggers `429` lockout after 5 failures. |
| **`POST /auth/logout`** | 401 | 200 | 200 | 200 | 200 | Clears session cookie. |
| **`GET /auth/me`** | 401 | 200 | 200 | 200 | 200 | Returns current authenticated user profile. |
| **`POST /documents`** | 401 | 403 | 403 | 201 | 403 | Uploads a new document (Owner only). |
| **`GET /documents`** | 401 | Allowed | Allowed | Allowed | Allowed | Search & list documents. Results strictly filtered by `visible_documents()`. |
| **`GET /documents/{id}`** | 401 | 200 / 404 | 404 | 200 / 404 | 404 | Returns document metadata. Returns `404` if unaccessible (anti-enumeration). |
| **`GET /documents/{id}/download`** | 401 | 200 / 404 | 404 | 200 / 404 | 404 | Downloads binary file content. Fully audited. |
| **`PATCH /documents/{id}`** | 401 | 403 / 404 | 404 | 200 / 404 | 404 | Updates document name or category (Manage permission required). |
| **`DELETE /documents/{id}`** | 401 | 403 / 404 | 404 | 204 / 404 | 404 | Soft-deletes document (Owner only). |
| **`GET /documents/{id}/grants`** | 401 | 403 / 404 | 404 | 200 / 404 | 404 | Lists active sharing grants for a document. |
| **`POST /documents/{id}/grants`** | 401 | 403 / 404 | 404 | 201 / 404 | 404 | Grants or updates permission for a user (`read` or `edit`). |
| **`DELETE /documents/{id}/grants/{gid}`** | 401 | 403 / 404 | 404 | 204 / 404 | 404 | Revokes an active grant. Takes effect on the very next request. |
| **`POST /documents/{id}/access-suggestions`** | 401 | 404 | 404 | 201 | 404 | Generates rule-based AI access suggestions from metadata. **Grants nothing.** |
| **`POST /documents/{id}/access-suggestions/{sid}/confirm`** | 401 | 404 | 404 | 201 | 404 | Human confirmation endpoint. Grants access *only* to candidates named in suggestion. |
| **`POST /documents/{id}/access-suggestions/{sid}/reject`** | 401 | 404 | 404 | 204 | 404 | Rejects suggestion and writes an audit log entry. |
| **`GET /admin/audit`** | 401 | 403 | 403 | 403 | 200 | Views system-wide immutable audit ledger. |
| **`GET /admin/audit/verify`** | 401 | 403 | 403 | 403 | 200 | Verifies cryptographic hash-chain integrity of the audit log. |
| **`GET /admin/alerts`** | 401 | 403 | 403 | 403 | 200 | Evaluates explainable risk rules over recent audit logs. |
| **`POST /admin/users`** | 401 | 403 | 403 | 403 | 201 | Creates new users with strict input validation and lowercased email normalization. |
| **`POST /admin/users/{id}/disable`** | 401 | 403 | 403 | 403 | 200 | Disables user account and instantly revokes all active sessions. |
| **`POST /admin/users/{id}/enable`** | 401 | 403 | 403 | 403 | 200 | Re-enables a disabled user account. |