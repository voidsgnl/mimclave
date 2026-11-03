# MIRAGE TOML Configuration

MIRAGE configuration is versioned TOML. The loader is side-effect free: it parses configuration but does not bind ports, start decoys, change firewall rules, or forward traffic.

## Top-level structure

- `version`: required integer; currently `1`.
- `profiles`: zero or more decoy profile tables.
- `mappings`: zero or more exposed listener-to-profile mappings.
- `protected_services`: optional inventory of real services. These records are not used to construct decoy identities.

## Decoy profile

Each `[[profiles]]` table requires:

| Key | Meaning |
| --- | --- |
| `id` | Unique profile identifier |
| `name` | Operator-facing name |
| `protocol` | One of `ssh`, `http`, `https`, `ftp`, `mysql`, `postgresql`, `smb`, `rdp`, `redis`, `custom` |
| `service_name` | Fabricated service identity |
| `service_version` | Fabricated version string |
| `hostname` | Decoy hostname |

## Listener mapping

Each `[[mappings]]` table requires `profile_id` and a `listener` inline table containing `host`, `port`, and optional `transport` (`tcp` by default; allowed values: `tcp`, `udp`).

Known TCP conventions are checked by default: 21/FTP, 22/SSH, 80/HTTP, 443/HTTPS, 445/SMB, 3306/MySQL, 3389/RDP, 5432/PostgreSQL, and 6379/Redis. Unknown ports are not assigned an assumed protocol. These are defaults, not hard-coded network law.

A deliberate mismatch must set `allow_nonstandard_protocol = true` and provide a meaningful `override_reason`. UDP mappings are not checked against the TCP convention table.

Each listener target may be mapped only once. Every mapping must reference an existing profile.

## Protected service inventory

Each `[[protected_services]]` table requires a unique `id` and an `endpoint` inline table. Optional `description` is for operator notes. The protected service's identity is intentionally separate from all decoy profiles.

## Validate

After installing the project and development dependencies:

```bash
mirage validate-config config/example.toml
mirage discover
```

Validation is offline and read-only. Exit code 0 means the configuration passed; 1 means policy validation issues; 2 means the file could not be parsed or structurally loaded.
