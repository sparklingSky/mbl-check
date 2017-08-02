**mbl_check.py**

This Python script is designed to check the list of IP addresses or subnet(s) via VirusTotal and output the status of the IP address if it is detected by at least one URL scanner or malicious URL dataset.<br />
Compatible with Python 3.x.<br />
Requires the following Python modules to be installed: requests, ipcalc + [ip_validator](https://github.com/sparklingSky/ip_validator) module.

How to use:<br />
	1. Specify 'ips' variable and uncomment the lines in the end of the script.<br />
	2. Run the script.<br />
	3. Output will be recorded to output_mbl.log<br />
