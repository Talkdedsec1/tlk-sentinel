# Reputation lists

Every `.txt` / `.list` file in this directory is loaded at startup. The file name
becomes the tag attached to matching IPs, so `tor-exit.txt` tags hits as `tor-exit`.

Format, one entry per line:

```
185.220.101.5           single address
45.9.9.0/24             CIDR range
203.0.113.7 some note   trailing text is ignored
# comment lines start with a hash
```

A match escalates the threat to `critical`, which in the `self` profile means an
immediate ban. Keep these lists conservative: a bad entry bans real users.

Useful public sources you can drop in here (download them yourself, this repo ships
no third-party data):

- Tor exit node list — `check.torproject.org/torbulkexitlist`
- Spamhaus DROP — `www.spamhaus.org/drop/drop.txt`
- FireHOL level 1 — `github.com/firehol/blocklist-ipsets`

Refresh them with cron; the agent re-reads the directory on restart.
