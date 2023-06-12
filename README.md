# Auto-RDNS-firewall-Python
*A python script designed to run automatically and unattended for server applications, that blocks traffics from other servers with a FQDN*

*The problem this script intended to solve is to deal with VPN-masked attaking traffic that is not possible to block with standard firewall infrustructures anymore*

This script is mainly used to block VPN traffic from large providers, but also works on blocking any traffic generated on servers with a FQDN, thus effectively shield the server from common attacking traffics. It currently doesn't support IPv6 due to development time restrictions, since processing IPv4 only is adequate to block large VPN providers' traffics.

The source code is only commented in Mandarin and Google/Bing Translate could handle that.

**This script consists:**
 - File IO
 - List, tuple & dictionary manipulation
 - Python socket module with multiprocessing
 - Indent control (maximum 3)

**This script reads and writes:**
 - ip-safe.txt & ip-block.txt from input file: ip-file.txt
 - Apache's deny.conf & allow.txt from Apache's input files \*access.log
 - For security, the \*access.log files are not presented here

The Apache implementation is caapble of handling 10,000~100,000 server access entries each time it runs, and it runs much faster than Python's socket module with multiprocessing coded.

**This script performs lots and lots of filtering to avoid:**
 - Blocking actual users
 - Save processing power or memory usage on deployed server
 - Allow manually specify permitted IP addresses eventhough they have a FQDN

**To test if this script works:**
 - Open the sample output file (ip-block.txt or deny.conf)
 - Perform an reverse DNS lookup (nslookup <ip-address>) on the addresses and see
 - Note: replace 'Deny from' to 'nslookup'
