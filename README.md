# TrustVault 🛡️

TrustVault is a secure document-sharing platform featuring strict role-based access controls, robust metadata-driven AI access suggestions, a tamper-evident hash-chained audit log, login brute-force protection, and automated administrative security alerts.

---

## Key Security Features

1. **Default-Deny Access Controls**: Every document retrieval, download, or modification passes through a single centralized `authorize()` gateway. Unauthorised access attempts return `404 Not Found` rather than `403 Forbidden` to prevent resource enumeration.
2. **Hash-Chained Audit Trail**: Every significant action (uploads, downloads, permission grants, denials, and login attempts) is recorded in an immutable-style audit log where each row's hash depends on the preceding row (`verify_chain()`). A database trigger prevents updates or deletions.
3. **Secure File Storage**: File binary data is stored inside a dedicated Postgres table mapped via random UUID storage keys, preventing path-traversal attacks and ensuring files persist safely across hosting redeploys.
4. **Brute-Force Login Lockout**: Every login attempt (success, failure, or block) is logged. An email address encountering 5 failed password attempts within a 15-minute window is temporarily locked out (`429 Too Many Requests`), checked *before* password verification.
5. **Metadata-Driven AI Access Suggestions**: Access recommendations are purely rule-based and derived from historical metadata (who an owner shared similar documents with in the past). The suggestion endpoint *grants nothing*—a separate human confirmation step is required, and both steps are fully audited.
6. **Admin Security Alerts**: Automated explainable rules flag suspicious activities such as repeated denied attempts, locked accounts, bulk downloads, permission grant bursts, and grants made to external email domains.

---

## Demo Accounts & Credentials

The database seed script (`python -m scripts.seed`) creates the following pre-configured demo users (all share the standard password: `SecurePassword123!`):

| Role | Email | Description |
| :--- | :--- | :--- |
| **Admin** | `admin@x.com` | Manages users, views security alerts, verifies audit log hash chains. |
| **Owner** | `owner@x.com` | Uploads documents, manages sharing permissions, runs AI suggestions. |
| **Viewer** | `viewer@x.com` | Views or edits documents specifically granted access to. |

---

## Local Development & Setup

### 1. Clone & Setup Virtual Environment
```bash
git clone [https://github.com/kumar100911/trustvault.git](https://github.com/kumar100911/trustvault.git)
cd trustvault

python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate