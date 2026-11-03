# Changelog

All notable project changes are documented here.

## Unreleased

### Added
- Created the initial project foundation and documented MIRAGE's purpose.
- Added immutable typed models for endpoints, decoy profiles, protected-service inventory, and listener mappings.
- Added protocol/port compatibility validation with explicit, reason-required overrides for nonstandard deployments.
- Added read-only Linux `/proc/net` discovery for TCP listeners and bound UDP sockets.
- Added unit tests for configuration validation and proc-table parsing.
- Added CI automation for supported Python versions.

### Security
- Discovery performs no active network probes, shell execution, firewall changes, or traffic interception.
- Real-service inventory remains separate from decoy identity configuration.
