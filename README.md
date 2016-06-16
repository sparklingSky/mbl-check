**mbl_check.py**

This Python script is designed to check IP addresses within the specified subnet via VirusTotal and/or CleanMx and output the status of the IP address if it is detected by at least one URL scanner or malicious URL dataset.<br />
Compatible with Python 2.x.<br />
Requires the following Python modules to be installed: requests, ipcalc.

How to use:<br />
	1. Specify 'net' variable.<br />
	2. Configure run at the end of file (follow the comments).<br />
	3. Run the script.<br />
	4. Output will be recorded to output_mbl.log<br />