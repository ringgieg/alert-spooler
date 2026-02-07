# alert-spooler

A small spooler that ingests alert files (`.warn`, `.alarm`), archives them into SQLite, flattens JSON, generates a normalized content hash label, and forwards events to Grafana Alloy via TCP syslog.

## Why
- Alert files are small and discrete; tailing them directly can miss data when files are moved/deleted quickly.
- This spooler reads each file atomically, archives raw content, and outputs stable syslog lines that Alloy can ingest.

## Build

```powershell
cd alert-spooler
go build ./...
```

## Run (example)

```powershell
./alert-spooler.exe --config .\config.yaml --deadman "spooler-run" --once
```

## Replay (example)

Resend archived events from a given time. Replay sends do not mutate the DB and are labeled with `replay="true"`.

```powershell
./alert-spooler.exe --config .\config.yaml --deadman "spooler-run" --replay-from "2026-02-07 00:00:00"
```

## Notes
- Syslog structured data includes `job`, `service`, `filename`, `alert_type`, `alert_level`, `hash`, `cccc`, and optional `replay`/`deadman`.
- Unit tests try to load fixtures from existing `notifier/**/alerts_*.db` raw_content; they fall back to an embedded sample if none found.
