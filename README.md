# erl_mouse
python script to find vulnerable targets of CVE-2025-32433 

This script scans CIDR blocks to find vulnerable targets of CVE-2025-32433.  

Using Masscan as the workhorse of the operation, erl_mouse continues the discovery by creating and parsing a JSON file of all IP addresses with port 22 open.  The JSON parses for Erlang/OTP SSH banner regex & vulnerability thresholds provding only viable targets.

Findings will print in terminal and also provide a .CSV and .JSON

In theory, at least.

Although there are presets to scan [by several countries (more will be added), by type (telecom, cloud, even IOT if you are inside that network), etc.], your best bet is probaly entering in your own set of CIDR.


*For education and security research*

### Requirements

- Python3
- Masscan 
