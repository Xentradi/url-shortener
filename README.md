# X3N LinkHub

Production-oriented link shortener API with API-key auth, admin operations, maintenance tooling, and OpenAPI docs.

## Features
- Short URL creation with idempotency per `(originalUrl, apiKeyId)`
- Redirect handling with expiration checks (`404` vs `410`)
- API-key scopes (`shorten:write`, `admin:*`, wildcard patterns)
- Admin key management (create, rotate, disable, delete)
- URL admin filters, pagination, soft-delete lifecycle (`deletedAt`, `purgeAt`)
- Maintenance endpoints for cleanup/backfill/index sync/nuke
- Request logging + admin audit trail
- Swagger UI docs from a single `openapi.yaml`
- Built-in web UI login at `GET /` with secure session cookie (no raw key stored in browser storage)

## Authentication Headers
- `X-API-Key`: required for `POST /shorten`
- `X-Admin-Key`: required for `/admin/*` and `/docs`
- `X-Admin-Nuke-Key`: required in addition to `X-Admin-Key` for `/admin/maintenance/nuke`

## Environment Variables
- `PORT` (default: `3000`)
- `MONGODB_URI` (default: `mongodb://localhost:27017/urlShortener`)
- `REDIRECT_URL` (default: `https://example.com`)
- `API_HOST` (default: `api.x3n.us`) - host that can access API and docs endpoints
- `WEB_HOSTS` (default: `x3n.us,www.x3n.us`) - comma-separated hosts for the web UI and redirect links
- `API_KEY_PEPPER` (recommended in production)
- `ADMIN_NUKE_KEY` (required to enable nuke endpoint)
- `DOCS_SESSION_SECRET` (optional, recommended in multi-instance deployments)
- `UI_SESSION_SECRET` (optional, recommended in multi-instance deployments)
- `SHORT_ID_LENGTH` (default: `6`)

## Install & Run
```bash
npm install
npm start
```

## Bootstrap Admin Key
```bash
npm run bootstrap:admin
```
This prints an admin key and a generated nuke key suggestion.

## API Docs (Swagger UI)
- Source of truth: `openapi.yaml`
- Host: API host (for example `https://api.x3n.us`)
- UI: `GET /docs` (requires `X-Admin-Key`)
- Raw spec: `GET /docs/openapi.yaml` (requires `X-Admin-Key`)

## Web UI
- Host: web host (for example `https://x3n.us`)
- `GET /` shows login or dashboard
- Supports API key or admin key login
- Admin sessions include extra dashboard panels (maintenance stats, API keys, recent global URLs)

## Health
- `GET /healthz` liveness
- `GET /readyz` readiness (MongoDB connection)
