# Changelog

All notable changes to SIB are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.6.0] - 2026-04-08

### Added
- 6 new obfuscator tests for real Falco alert patterns (`container_id=host`, system users, hex IDs)
- Auto-detection of host IP for `make install-analysis` (no interactive prompt)
- `ANALYSIS_BIND` and `ANALYSIS_HOST` settings in `.env.example`

### Fixed
- Falco upgraded from 0.39.2 to 0.40.0 (fixes `scap_init` crash on kernel 6.12+)
- `make test-rules` pinned to `falco:0.40.0` (was using `:latest`)
- `test-pipeline.sh` access URLs now correctly show `127.0.0.1` for localhost-bound services
- Privacy banner in analysis UI no longer claims data was obfuscated when nothing changed
- Falco config generator improved with output format and metrics settings

### Changed
- `make install-analysis` no longer prompts for IP — auto-detects via `hostname -I` with fallback chain (CLI arg → `.env` → auto-detect)
- Detection rules consolidated and refined

---

## [Unreleased]

### Added
- Rule packs for cloud and web server environments (`cloud_rules.yaml`, `webserver_rules.yaml`)
- `docs/upgrade.md` with upgrade instructions
- `docs/kubernetes.md` documenting sib-k8s integration

---

## [0.5.0] - 2026-04-08

### Added
- Container images published to GHCR (`ghcr.io/matijazezelj/sib-analysis`, `sib-ansible`)
- CI workflow to build and push images on every push to `main` and on version tags
- 35 automated tests for the `analysis/` obfuscator module
- 5 new detection rules: SSH authorized keys modification (T1098.004), shell profile
  modification (T1546.004), at job scheduling (T1053.002), firewall rule tampering
  (T1562.004), network sniffing tool launch (T1040)
- Demo script coverage for all new detection rules (12 MITRE ATT&CK categories)

### Fixed
- GitHub Actions Node.js 20 deprecation warnings (upgraded `actions/checkout` to v6)
- `sigma2sib` field modifier parsing (`Image|endswith` was treated as a single field name)
- Operator precedence bug in Firewall Rules Modified detection rule
- `analysis/` Docker image missing `templates/` directory (caused `TemplateNotFound` crash)
- All semgrep security findings in `analysis/api.py` (NaN injection, SSTI, HTTP transport)

### Changed
- Sigma converter README documents wildcard selector and nested logic limitations
- CI `lint` job added (shellcheck + ruff)

---

## [0.4.0] - 2026-02-10

### Added
- Fleet deployment via Ansible (Dockerized, no local Ansible install needed)
- mTLS support for encrypted fleet communication
- `make backup` / `make restore` for storage volumes and configuration
- AI-powered alert analysis with obfuscation (Anthropic, OpenAI, Ollama)
- 65 detection rules mapped across all 12 MITRE ATT&CK tactics
- Grafana data link integration for one-click alert analysis
- `make doctor` target for diagnosing common issues
- `make demo` with realistic multi-category security event generation

### Fixed
- Fleet dashboard host filter
- mTLS certificate distribution via Ansible
- 30+ Makefile target bugs and documentation issues

---

## [0.3.0] - 2025-12-01

### Added
- Sigma rule converter (`sigma/sigma2sib.py`) with MITRE tag preservation
- Threat intelligence IP blocklist feeds (`threatintel/`)
- Custom Grafana dashboards: Security Overview, Events Explorer, MITRE ATT&CK matrix
- VictoriaLogs + VictoriaMetrics stack (10x less RAM than Loki/Prometheus)
- Remote collector support (Vector/vmagent for vm stack, Alloy for grafana stack)

### Changed
- Default storage stack switched from `grafana` to `vm`
- All sensitive API keys moved to `.env` with Docker Secrets `_FILE` pattern support

---

## [0.2.0] - 2025-10-01

### Added
- Dual storage stack support (`STACK=vm` / `STACK=grafana`)
- Falcosidekick alert routing with webhook and Slack output
- `make test-alert` and `make test-rules` targets
- Onboarding docs: minimal install, FAQ, hardening guide, troubleshooting

---

## [0.1.0] - 2025-08-01

### Added
- Initial release: one-command security monitoring stack
- Falco eBPF syscall detection
- Grafana visualization
- Docker Compose orchestration via Makefile
- CI pipeline with Docker Compose validation
