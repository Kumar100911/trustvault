# API: who may call what
Every document route returns 404 (never 403) when the person may not act on it.

| Method and path | Anonymous | Viewer | Owner | Admin | Notes |
|---|---|---|---|---|---|
| POST /auth/login | yes | yes | yes | yes | |
| POST /auth/logout, GET /auth/me | 401 | yes | yes | yes | |
| POST /documents | 401 | 403 | yes | 403 | upload, owner role only |
| GET /documents | 401 | own+granted | own+granted | own+granted | admin sees only what they were granted |
| GET /documents/{id}, /download | 401 | read grant | owner or read/edit grant | same as viewer | |
| PATCH /documents/{id} | 401 | edit grant | owner or edit grant | same | rename, category |
| DELETE /documents/{id} | 401 | no (404) | owner only | no (404) | soft delete |
| GET/POST /documents/{id}/grants | 401 | no (404) | owner only | no (404) | manage |
| DELETE /documents/{id}/grants/{gid} | 401 | no (404) | owner only | no (404) | grant must belong to that document |
| GET /admin/audit, /audit/verify, /users | 401 | 403 | 403 | yes | |
| POST /admin/users/{id}/disable, /enable | 401 | 403 | 403 | yes | cannot disable self |