# Pelican to Mikrotik Sync

A script to synchronize Pelican allocations to a Mikrotik router's firewall settings as NAT rules.

## Configuration

The script is configured via environment variables.

### Pelican API information
| Variable | Default | Description |
| -------- | ------- | ----------- |
| `PELICAN_API_KEY` | required | The API key to access Pelican.  Must have at least read-only permissions for Server, Allocation, and Node |
| `PELICAN_API_BASE_URL` | `''` | The base URL for the Pelican server, like `https://my.pelican.server` |

### Mikrotik API information
| Variable | Default | Description |
| -------- | ------- | ----------- |
| `MIKROTIK_API_BASE_URL` | `''` | The base URL for the Mikrotik firewall, like `https://my.mikrotik.router` |
| `MIKROTIK_API_USERNAME` | required | The username for the Mikrotik firewall |
| `MIKROTIK_API_PASSWORD` | required | The password for the Mikrotik firewall
| `MIKROTIK_API_RULE_IDENTIFIER` | `'Pelican-to-Mikrotik'` | A string used to identify a rule as having been set by this script. Only rules containing this string in the comments will ever be deleted. |
| `MIKROTIK_API_RULE_TEMPLATE` | `'{}'` | A JSON dictionary that allows setting additional parameters not tracked by Pelican.  Use like `MIKROTIK_API_RULE_TEMPLATE='{"dst-address-list": "!gateways", "dst-address-type": "local"}'` |