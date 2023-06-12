# Auto-RDNS-firewall-Python
*A python script designed to run automatically and unattended for server applications, that blocks traffics from other servers with a FQDN*

This script is mainly used to block VPN traffic from large providers, but also works on blocking any traffic generated on servers with a FQDN, and it does not support IPv6 due to development time restrictions since working on IPv4 is adequate to block large VPN providers' traffics, which means all IPv6 traffics are automatically allowed.

**This script consists:**
 - File IO
 - List, tuple & dictionary manipulation
 - Python socket module with multiprocessing

**This script reads and writes:**
 - ip-safe.txt & ip-block.txt from input file: ip-file.txt
 - Apache's deny.conf & allow.txt from Apache's input file \*access.logs

The Apache implementation is designed to handle 10,000~100,000 access entries each time it runs

**This script performs lots and lots of filtering to avoid:**
 - Causing trouble to real website users
 - Save processing power or memory on deployed server
 - Allow manually specify permitted IP addresses eventhough they have a FQDN

**To test if this script works:**
 - Open the sample output file (ip-block.txt or deny.conf)
 - Perform an reverse DNS lookup (nslookup <ip-address>) on the addresses and see
