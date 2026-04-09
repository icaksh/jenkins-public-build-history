JENKIS HISTORY

Overview

Jenkis History is a Go application for browsing Jenkins jobs and build history with controlled access.
It provides an access-code based user flow, an admin panel, live build updates, hook delivery, and SQLite-based persistence.


Features

- Access-code based user access
- Admin login with signed cookie session
- SPA-like folder and pipeline browsing
- Build history with branch, commit, and stage information
- Live updates using SSE
- Running builds dashboard
- User-managed Telegram and webhook hooks
- Background Jenkins notifier
- SQLite persistence
- Audit logging
- Basic hardening for CSRF, same-origin checks, and hook encryption at rest

Requirements

- Go 1.25 or newer
- A reachable Jenkins instance
- Jenkins API credentials
- Telegram bot token and chat ID if Telegram notifications are used

Configuration

The application reads configuration from .env and environment variables.

Main variables

JENKINS_URL=http://jenkins.internal:8080
JENKINS_USER=your-username
JENKINS_TOKEN=your-api-token
PORT=3000
BUILD_LIMIT=10
NOTIFY_POLL_INTERVAL=10s
NOTIFY_ACTIVE_POLL_INTERVAL=2s
ADMIN_PASSWORD=change-this-now
SESSION_SECRET=replace-with-a-random-secret
HOOK_ENCRYPTION_KEY=replace-with-a-random-secret
DB_PATH=data.db

Branding variables

APP_NAME=Build History
APP_DESCRIPTION=Jenkins read-only external workspace
APP_ICON=fa-solid fa-hammer
APP_LOGO_URL=

Branding notes

- APP_NAME controls the application title.
- APP_DESCRIPTION controls the short subtitle shown in the UI.
- APP_ICON uses a Font Awesome class name.
- APP_LOGO_URL is optional. If it is set, the UI uses the logo image instead of the icon.

Security notes

- Set SESSION_SECRET explicitly in production.
- Set HOOK_ENCRYPTION_KEY explicitly in production.
- Use HTTPS in production.
- Treat access cookies and admin cookies as bearer credentials.

Running locally

1. Copy .env.example to .env
2. Adjust the values
3. Start the application

Command:

   go run .

Default address:

   http://localhost:3000

Important note:

Do not run the app with:

   go run main.go

This project uses multiple files in package main, so the correct command is:

   go run .

Build script

This repository includes build.sh.

Commands:

   ./build.sh
   ./build.sh build
   ./build.sh run
   ./build.sh clean

Default binary output:

   ./bin/jenkis-history

Docker

Files included:

- Dockerfile
- docker-compose.yml

Run with Docker Compose:

   docker compose up --build

Container notes

- The compose file reads values from .env
- SQLite data is persisted through:

   ./data -> /app/data

- Inside the container, the database path is:

   /app/data/data.db

Authentication model

- End users authenticate with an access code
- Admin users authenticate with ADMIN_PASSWORD
- Sessions are stored in signed cookies

Hooks

Supported hook types:

1. Telegram
   Requires bot token and chat ID

2. Webhook
   Requires a target URL

Notification behavior

- A background worker polls Jenkins
- Final notifications are sent for terminal build states
- Telegram live messages are updated while builds are active

Storage

- SQLite is used for persistence
- Hook values are encrypted before they are written to the database
- SQLite WAL side files may appear during runtime

Expected SQLite files

- data.db
- data.db-wal
- data.db-shm

Project structure

- main.go
- notifier.go
- jenkins/client.go
- db/
- templates/
- static/
- build.sh
- Dockerfile
- docker-compose.yml

Operational guidance

- This application is suitable for internal usage
- It includes practical security improvements, but it is not a fully hardened internet-facing platform
- For production deployment, use strong secrets, HTTPS, and controlled outbound network policy


LICENSE
The copyright holder grant the freedom
to copy, modify, convey, adapt, and/or redistribute this work
under the terms of the Apache2.0 License.

Palguno Wicaksono <hello@icaksh.my.id>
