# erl_mouse

##### WORKING ON COMPLETE OVERHAUL OF SCRIPT INTO THE WEE HOURS (v1.1)
- New RabbitMQ + CouchDB blocks to scan (all use the vulnerability but its just a matter of finding one not patched)
- Debug output into CV + JSON
- China supposedly the most likely country to have this CVE so why not scan ALL of China.  Yup, all 350,000,000+ IP's lol
- Status bar for those scans longer than our ADHD/patience can handle

  
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
