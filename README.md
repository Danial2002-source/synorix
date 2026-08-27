# Synorix

**Synorix** is a security orchestration platform for web application traffic inspection, WAF rule management, IDS/IPS monitoring, compression/deduplication controls, and secure authenticated access.

This repository combines a React frontend, an Express/SQLite backend, and a Go-based security proxy with Suricata integration.

---

## The problem

Modern security stacks often require multiple tools and siloed dashboards for firewall rules, IDS/IPS events, traffic monitoring, and policy enforcement. That makes it hard to manage attack surface, block malicious traffic reliably, and maintain a secure operations workflow.

Synorix brings these capabilities together with:

- centralized rule and policy management
- secure access control for administrators and users
- real-time request logging and analytics
- integration with a Go security proxy and Suricata for network-level detection and blocking

---

## What it does

Synorix provides:

- User authentication, admin/user roles, and secure session handling
- Admin dashboards for firewall, IDS/IPS, proxy, compression, and deduplication management
- Detailed request logging and traffic analytics
- Integration with a Go security proxy for TLS termination, request filtering, and active blocking
- Support for Suricata alert ingestion and enrichment
- Configurable deployment through environment variables and secure internal service tokens

---

## Features

### Security operations

- Admin-managed firewall and WAF rule controls
- IDS/IPS event monitoring and rule status handling
- Compression and deduplication management for traffic optimization
- Proxy settings and secure request forwarding
- Real-time request log search, export, and analytics

### User and admin workflows

- Signup / login flows with JWT authentication
- Role-based access for admin and standard users
- Admin user management and audit logging
- Protected routes across the React application

### Deployment & architecture

- React + Vite frontend served locally on port 3000 in development
- Node.js Express backend on port 3001
- SQLite database for user, audit, and log persistence
- Go security proxy in `security-proxy/` for external traffic handling
- Suricata integration under `services/suricata/` for IDS/IPS event feeds

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite |
| Backend | Node.js, Express, SQLite |
| Proxy | Go |
| Security | Helmet, express-rate-limit, JWT, CORS |
| Monitoring | Request logging, SSE / event streaming |

---

## Getting started

### Prerequisites

- Node.js 18+
- npm
- Go 1.20+ (for the security proxy)
- Optional: Suricata for IDS/IPS integration

### 1. Clone the repo

```bash
git clone <repo-url>
cd synorix
```

### 2. Install dependencies

```bash
npm install
```

### 3. Configure environment

Copy the example production environment file and update the values for your deployment:

```bash
cp .env.production.example .env
```

Important settings:

- `JWT_SECRET` — strong secret for signing tokens
- `INTERNAL_API_TOKEN` — shared token used between backend and proxy
- `SECURITY_PROXY_URL` / `BACKEND_URL` — internal service URLs
- `TLS_CERT` / `TLS_KEY` — paths to proxy TLS certificates

---

## Running locally

### Start the backend

```bash
npm run server
```

This starts the Express backend on `http://localhost:3001`.

### Start the frontend

```bash
npm run dev
```

This starts the Vite app on `http://localhost:3000` and proxies `/api` to the backend.

### Start the Go security proxy

Build and run the proxy from `security-proxy/`:

```bash
cd security-proxy
go run main.go
```

If you want a production-style build, use:

```bash
go build -o synorix-security-proxy ./main.go
```

---

## Project structure

- `frontend/` — React application source code and static assets
- `server/` — Express backend, routes, middleware, SQLite database setup
- `security-proxy/` — Go proxy and TLS termination code
- `services/` — supporting services, Suricata, firewall tooling, performance tools, and auxiliary utilities
- `scripts/` — repository helper scripts such as admin bootstrap and API tooling
- `docs/` — deployment guides, architecture notes, and project documentation

---

## Usage

Live demo: https://synorix.vercel.app/

1. Open the app at `http://localhost:3000`
2. Register or log in
3. Use admin dashboards to manage firewall, IDS/IPS, proxy, and traffic policies
4. View request logs, analytics, and security events

---

## Notes

- Do not expose the Node.js backend directly to the public internet in production.
- Keep `INTERNAL_API_TOKEN` and `JWT_SECRET` private.
- Use proper TLS certificates for the Go security proxy.
- After bootstrap admin creation, disable or remove the bootstrap password variables.

---

## License

This project is released under the MIT License. See `LICENSE` for details.
