# Usage

## Looking up IP addresses

Pass one or more addresses on the command line:

```
ip_info 1.2.3.4 8.8.8.8       # or the short alias: ipi
```

![usage - command line](img/ip_info-1753415554661.webp)

If you don't pass any addresses, `ip_info` reads the text on your clipboard and
extracts any IP addresses it finds. Invalid and reserved addresses are
discarded:

```
ip_info
```

![usage - clipboard](img/ip_info-1753417887180.webp)

## Output format

View the results as a table with `--output table` (the default):

![output - table](img/ip_info-1753417991342.webp)

Or view the raw JSON with `--output rawjson`:

```
ip_info 1.2.3.4 --output rawjson
```

![output - rawjson](img/ip_info-1753418532254.webp)

## Choosing which providers to query

By default, `ip_info` queries every provider that has a key saved in the keyring,
plus every provider that does not require a key.

To query specific providers, use `--apis` with one or more provider names:

```
ip_info 1.2.3.4 --apis virustotalcom ipqueryio
```

![output - specific api](img/ip_info-1753420108640.webp)

!!! note
    The output shows data from every provider that has results saved in the
    local database for the given IP, even if you only queried a subset this run.

See **[Providers](providers.md)** for the full list of provider names and how to
add API keys.
