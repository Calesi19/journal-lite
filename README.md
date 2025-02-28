![journal-lite](docs/banner.webp)

# journal-lite

A simple journaling app that allows you to write and save journal entries. The goal was to build an entire full-stack, server-side rendered app with one executable.

Built with:

- SQLite / Turso
- Go
- HTMX
- Pico CSS

## Deploy as Container

For a quick deployment, you can run the Docker image from GitHub Container Registry. The container will create its own SQLite database.

```bash
docker run -p 8080:8080 ghcr.io/calesi19/journal-lite:latest
```

## Installation

1. Clone the repository

```bash
git clone https://github.com/Calesi19/journal-lite.git
```

2. Build the app

```bash
go build
```

3. Run the app

```bash
./journal-lite
```

## Turso

The app can be used with a Turso database. Setup the database url and authentication token in the environmnet variables.

```bash
export TURSO_DATABASE_URL="libsql://example-database.turso.io"
export TURSO_AUTHENTICATION_TOKEN="eyJdlfieale23C34eLSEa223ElaDfa...."
```

## Deploy with Docker

1. Build the Docker image

```bash
docker build -t journal-lite .
```

2. Run the Docker container

```bash
docker run -p 8080:8080 journal-lite
```

or run with docker container with Turso database

```bash
docker run -p 8080:8080 -e TURSO_DATABASE_URL="libsql://example-database.turso.io" -e TURSO_AUTHENTICATION="eyJdlfieale..." journal-lite
```

3. Open the app in your browser

```bash
http://localhost:8080
```
