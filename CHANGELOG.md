# Changelog

All notable changes to this project will be documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

Per-version release notes for tagged releases are published on the [GitHub Releases page](https://github.com/WYRE-AI/bitdefender-mcp/releases) - `semantic-release` generates them from commit history at release time.

## [Unreleased]

### Added

- Initial v1 release: 10 read-only tools covering endpoint/network inventory (endpoints, managed-endpoint detail, custom groups, network inventory items, scan tasks), security policies, the account-wide malware-hash Blocklist, and scheduled/instant reports. HTTP Basic authentication (API key as username, empty password) against Bitdefender GravityZone's **JSON-RPC 2.0** API - a new call shape for this catalog (every other Conduit sidecar calls REST). See README's Authentication and Scope sections for the full accounting of excluded mutating methods and the credential-scope finding (a GravityZone API key is scoped per API area, not per method).
