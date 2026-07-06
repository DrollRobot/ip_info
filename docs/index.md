# ip_info

A Python command-line tool for quickly querying IP address information from
multiple providers.

Because results are often inconsistent between providers, the most reliable
approach is to check several at once. `ip_info` does that for you: it queries up
to 15 free providers in parallel and returns geolocation and reputation
information in a few seconds.

It:

- Checks up to 15 free providers in parallel and returns results in seconds.
- Accepts IPv4 and IPv6 addresses, and supports bulk queries where the provider
  allows it.
- Validates addresses first, discarding invalid and reserved IPs to avoid
  wasting queries.
- Can parse IP addresses out of clipboard text for easier multi-IP input.
- Keeps a local SQLite database of past queries to avoid looking up the same IP
  twice.

## Installation

Clone the repository:

```
git clone https://github.com/DrollRobot/ip_info.git
cd ip_info
```

Install with [uv](https://docs.astral.sh/uv/) (recommended):

```
uv tool install .
```

Or with your system interpreter:

```
pip install .
```

## Quick start

Look up one or more addresses directly:

```
ip_info 1.2.3.4 8.8.8.8      # or the short alias: ipi
```

With no addresses given, `ip_info` reads the clipboard and extracts any IP
addresses it finds:

```
ip_info
```

Choose the output format (`table` is the default) or restrict which providers
are queried:

```
ip_info 1.2.3.4 --output rawjson
ip_info 1.2.3.4 --apis virustotalcom ipqueryio
```

## API keys

Four of the providers need no key; the rest require free registration. Keys are
stored encrypted at rest via the `keyring` library. Add one interactively with:

```
ip_info_keys
```

See the [README](https://github.com/DrollRobot/ip_info#apis) for the full list
of supported providers and their registration links.

## API reference

See the [Reference](reference/ip_info.md) page for the auto-generated API
documentation.
