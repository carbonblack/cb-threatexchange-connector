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

## Troubleshooting

If you suspect a problem, please first look at the ThreatExchange connector logs found here: 
`/var/log/cb/integrations/threatexchange/threatexchange.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

## Contacting Bit9 Developer Relations Support

Web: https://community.bit9.com/community/developer-relations
E-mail: dev-support@bit9.com

### Reporting Problems

When you contact Bit9 Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity
