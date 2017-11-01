# Carbon Black - ThreatExchange Connector

Carbon Black provides integration with ThreatExchange by retrieving Indicators of
Compromise (IOCs) from specified communities. To support this integration, Carbon
Black provides an out-of-band bridge that communicates with the 
[ThreatExchange API](https://developers.facebook.com/docs/threat-exchange).

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-threatexchange-connector
```

Once the software is installed via YUM, copy the 
`/etc/cb/integrations/threatexchange/connector.conf.example` file to 
`/etc/cb/integrations/threatexchange/connector.conf`.
 Edit this file and place your Carbon Black API key into the 
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Once you have the connector configured for your API access, start the ThreatExchange service:
```
service cb-threatexchange-connector start
```

Any errors will be logged into `/var/log/cb/integrations/threatexchange/threatexchange.log`.

## Changelog

### Version 1.2

Version 1.2 adds a custom User-Agent to the HTTP requests made to ThreatExchange.

### Version 1.1 

Version 1.1 of the ThreatExchange connector introduces persistent storage for historical ThreatExchange feed data.
The connector will now only query for new indicators that have been produced since the last time it was run (by default,
every two hours; configurable via `feed_retrieval_minutes` in the configuration file) and store all indicators for a 
maximum duration (by default, 7 days; configurable via `tx_historical_days` in the configuration file).

The feed data is stored in a SQLite database in `/usr/share/cb/integrations/threatexchange/db/threatexchange.db`.

## Troubleshooting

If you suspect a problem, please first look at the ThreatExchange connector logs found here: 
`/var/log/cb/integrations/threatexchange/threatexchange.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

## Contacting Carbon Black Developer Relations Support

Web: https://community.carbonblack.com/community/developer-relations
E-mail: dev-support@carbonblack.com

### Reporting Problems

When you contact Carbon Black Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, Cb Response Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity
