# Install

## Prerequisites

If it is not already installed, install [git](https://git-scm.com/).

Clone the repository:

```
git clone https://github.com/DrollRobot/ip_info.git
cd ip_info
```

## Recommended: install with uv

Install [uv](https://docs.astral.sh/uv/) if you don't have it, then from the
repository root (where `pyproject.toml` is) run:

```
uv tool install .
```

This installs the `ip_info` command (and its aliases) onto your PATH in an
isolated environment.

## Alternative: install with pip

Using your system interpreter:

```
pip install .
```

## Commands

Installing provides these commands:

| Command | Purpose |
|---|---|
| `ip_info` | Look up one or more IP addresses (alias: `ipi`). |
| `ip_info_keys` | Store or update provider API keys. |
| `import_ip2proxy` | Import an IP2Proxy LITE CSV dataset into the local database. |

See **[Usage](usage.md)** to get started.
