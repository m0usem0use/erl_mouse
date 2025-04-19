# erl_mouse version 1.1

##### Alright, I've improved several things to increase chances of finding a vulnerable device or network.  Most are not public facing, have been patched, or are so oscure that it can be difficult to find a target. 
Nevertheless, we persist.  You can now scan every IP address in china by choosing "Type Presets" and then choose from the amount of blocks you want to scan at one time.  There are over 300 million IP addresses so take it easy.  Haha.
There are other more tailored categories to choose from that you may have a better chance with.  RabbitMQ and CouchDB IP blocks will typically use the vulnerable SSH service.  Okay, good luck with ERL MOUSE (v1.1)

  
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
- china_ip_ranges.txt needs to be in same directory folder as erl_mouse_v1-1.py
