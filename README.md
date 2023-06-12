# Auto-RDNS-firewall-Python
A python script designed to run automatically and unattended for server applications, that blocks traffics from other servers with a FQDN
This script is mainly used to block VPN traffic from large providers, but also works on blocking any traffic generated on servers with a FQDN.

This script consists:
 - File IO
 - List, tuple & dictionary manipulation
 - Python socket module with multiprocessing

This script generates:
 - ip-safe.txt & ip-block.txt from input file: ip-file.txt
 - Apache's deny.conf & allow.txt from Apache's input file \*access.logs
