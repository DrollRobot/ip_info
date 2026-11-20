# Usage

## Looking up IP addresses

Pass one or more addresses on the command line:

```
ip_info 1.2.3.4 8.8.8.8
ipi 1.2.3.4 8.8.8.8         # short alias: ipi
ip_info                     # with no arguments, scans clipboard for ip addresses
```

## Output format

View the results as a table with `--output table` (the default):

Or view the raw JSON with `--output rawjson`:

```
ip_info 1.2.3.4 --output rawjson
```

## Choosing which providers to query

By default, `ip_info` queries every provider that has an API key set, plus
every provider that does not require a key.

To query specific providers, use `--apis` with one or more provider names:

```
ip_info 1.2.3.4 --apis virustotalcom ipqueryio
```

!!! note
    The output shows data from every provider that has results saved in the
    local database for the given IP, even if you only queried a subset this run.

See **[Providers](providers.md)** for the full list of provider names and how to
add API keys.

## Settings and the lookup database

Lookups are cached in a SQLite database in your user data folder.
`ip-info-config show` prints its location (`db_path`) along with every other
setting; `ip-info-config set db_path <file>` points it at another file.

To keep separate settings and keys, for example for work and home, use
profiles: `ip-info-config init --profile work`, then `ip_info --profile work ...`.
