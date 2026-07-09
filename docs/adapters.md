# Tool Adapters

Identity Nexus combines OSINT tools through subprocess adapters. Each adapter is
defined in TOML, so you can update command names, flags, wrapper scripts, API
keys, and output paths without changing Python code.

Placeholders available in every command:

- `{target}`: normalized input target
- `{target_kind}`: `email`, `phone`, or `username`
- `{email}`: normalized email when the target is an email
- `{phone}`: normalized phone number when the target is a phone number
- `{username}`: username target, or the local-part derived from an email
- `{output_json}`: per-tool JSON artifact path
- `{output_txt}`: per-tool text artifact path
- `{output_dir}`: per-tool artifact directory

The default artifact root is `~/.identity-nexus/artifacts/<scan-id>/`.

## Registered Tools

| Tool | Target types | Default mode | Notes |
| --- | --- | --- | --- |
| Blackbird | username, derived email username | passive | Runs after deriving a username from an email local-part. |
| Holehe | email | passive | Email registration checks. |
| GHunt | email | session | Requires a local GHunt session/auth setup before useful execution. |
| Maigret | username, derived email username | passive | Username checks across many sites. |
| Sherlock | username, derived email username | passive | Username checks across social networks. |
| WhatsMyName | username, derived email username | passive | The upstream project is commonly data-first, so point this to your preferred CLI/wrapper. |
| socialscan | email, username | passive | Registration checks for email or username targets. |
| PhoneInfoga | phone | passive | Phone number OSINT scan. |
| Ignorant | phone | passive | Phone registration checks. |
| h8mail | email | passive | Configure provider keys separately when needed. |
| SpiderFoot | email, phone, username | deep | Disabled by default; tune modules and output handling before enabling. |
| Recon-ng | email, phone, username | deep | Disabled by default; configure a non-interactive wrapper or resource script. |

## Example Wrapper

When a tool is interactive, needs a custom environment, or has changing CLI
flags, create a wrapper script and point the adapter at it:

```toml
[tools.recon_ng]
enabled = true
accepts = ["email", "phone", "username"]
risk = "deep"
command = ["/opt/identity-nexus/bin/recon-ng-wrapper", "{target}", "{target_kind}", "{output_json}"]
timeout_seconds = 900
```

Wrappers should write machine-readable output to `{output_json}` when possible
and exit non-zero when the tool fails.

## Operating Notes

- `enabled = false` removes a module from default scans. Explicitly requesting a
  disabled module returns a skipped result instead of running it.
- `risk = "deep"` keeps a module out of standard scans unless the request uses
  `include_deep = true`.
- Missing executables are reported per module as `not_installed`; the scan still
  completes and shows install hints.
- Dry runs expand command templates without checking whether executables exist.
