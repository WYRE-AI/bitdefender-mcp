# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

Per-version release notes for tagged releases are published on the [GitHub Releases page](https://github.com/WYRE-AI/bitdefender-mcp/releases) - `semantic-release` generates them from commit history at release time.

## [Unreleased]

### Added

- Initial v1 release: 10 read-only tools covering endpoint/network inventory (endpoints, managed-endpoint detail, custom groups, network inventory items, scan tasks), security policies, the account-wide malware-hash Blocklist, and scheduled/instant reports. HTTP Basic authentication (API key as username, empty password) against Bitdefender GravityZone's **JSON-RPC 2.0** API - a new call shape for this catalog (every other Conduit sidecar calls REST). See README's Authentication and Scope sections for the full accounting of excluded mutating methods and the credential-scope finding (a GravityZone API key is scoped per API area, not per method).
- Read-only incident and quarantine tools contributed by Adrian Waterfall (@AdrianCititec) in #5: `bitdefender_list_incidents` and `bitdefender_get_incident` (Incidents API v1.2, with filters, date-pair validation, and pagination) and `bitdefender_list_quarantine_items` (quarantine/computers v1.0).
- `BITDEFENDER_MAX_UPSTREAM_BYTES` setting. Default 16 MiB, ceiling 128 MiB; missing, blank, invalid, or non-positive values fall back to the default.

### Changed

- Upstream responses are now capped and streamed through `readBoundedText`. Responses above the limit fail with `BitdefenderApiError`. Invalid JSON now raises `BitdefenderApiError`.
- HTTP 403 messages now use Control Center area names (for example "Incidents" and "Quarantine").
- `BitdefenderApiArea` now includes `quarantine/computers`. `BitdefenderApiVersion` is added. Incident and quarantine types are exported.
