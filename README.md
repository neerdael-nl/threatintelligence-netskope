# threatintelligence-netskope
Ingest OSINT (Open Source) Threat Intelligence directly in Netskope.<br>
It is required to fill in the correct API tokens and Tenant name in your config.json in order for the tool to work.  (Tenant name takes the format of **name.region**, except for some regions like our main US management environment only where you only need to enter **name**, script has been updated for better json handling and added a dnsoverhttps feed.

Currently includes the following feeds:

dnsoverhttps: https://download.dnscrypt.info/resolvers-list/json/public-resolvers.json,<br>
rescure_ip: https://rescure.me/rescure_blacklist.txt,<br>
cins_ip: http://cinsscore.com/list/ci-badguys.txt,<br>
feodo_recommended_ip: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt,<br>
feodo_ip: https://feodotracker.abuse.ch/downloads/ipblocklist.txt,<br>
urlhaus_url: https://urlhaus.abuse.ch/downloads/text/,<br>
emergingthreats_tor_snort: https://rules.emergingthreats.net/blockrules/emerging-tor.rules,<br>
rescure_domain: https://rescure.me/rescure_domain_blacklist.txt,<br>
securityscorecard_ip: https://raw.githubusercontent.com/securityscorecard/SSC-Threat-Intel-IoCs/master/KillNet-DDoS-Blocklist/ipblocklist.txt,<br>
rutgers_ip: https://report.cs.rutgers.edu/DROP/attackers,<br>
emergingthreats_ip: http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt,<br>
banlist_ip: https://www.binarydefense.com/banlist.txt,<br>
digitalside_ip: https://osint.digitalside.it/Threat-Intel/lists/latestips.txt,<br>
digitalside_url: https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt,<br>
digitalside_domain: https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt,<br>
abusetracker_ip: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt,<br>
ipsum_ip: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt,<br>
jamesbrine_ip: https://jamesbrine.com.au/iplist.txt,<br>
malshare_hash: https://www.malshare.com/daily/malshare.current.sha256.txt,<br>
malware_bazaar_hash: https://bazaar.abuse.ch/export/txt/sha256/recent/,<br>
openphish_url: https://openphish.com/feed.txt,<br>
phishtank_csv: http://data.phishtank.com/data/online-valid.csv,<br>
abusetracker_ip: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt,<br>
threatminer_url: https://www.threatminer.org/getData.php?e=malware_container&q=malware_delivery&t=21&rt=3&p=1,<br>
firehol_ip: https://iplists.firehol.org/files/firehol_level1.netset,<br>
blocklist_ip: http://lists.blocklist.de/lists/dnsbl/all.list,<br>

You will need a REST API v2 key for managing URL-lists, the token requires URLLIST permissions:
https://docs.netskope.com/en/rest-api-v2-overview-312207.html

And a REST API v1 key for managing file profiles (ingesting malware hashes):
https://docs.netskope.com/en/rest-api-v1-overview.html

This tool only creates new URL Lists  and uses the name of feed as name of list, if the list already exists nothing happens (we need to add logic to then update the list :)
As for file profiles make sure your profile already exists and be aware it will be overridden, they can't be created using the API.
