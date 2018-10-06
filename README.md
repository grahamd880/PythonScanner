# PythonScanner

Using Python with Scapy to create a custom port scanner (TCP ONLY)

**NOTE**

I developed this all in Kali linux because it has Scapy on it locally. If you are developing on another distro you need to use the following command:

```pip install scapy```

This will enable you to use the scapy module in the script.


**USAGE:**

python scanner.py [-H <Host(s)> [-p <Port(s)> | -ps | -T | -a] [-wh]]

If the host flag is not selected the gui version of the program will start:

```python scanner.py```

-H Host(s)     - The host to scan (valid form examples: 10.10.10.5-15 or 10.10.10.2,10.10.10.7 or 10.10.10.0/24)

-p Ports    - The ports to scan. If flag not used the default is ports 1-1080. (valid form examples: -p 1-5 or -p 60,20,5 or -p 80)

-ps         - If this flag is selected a pingsweep is performed on the host(s) given

-T          - If this flag is selected a traceroute is performed on the host(s) given and then displayed

-a          - If this flag is selected a pingsweep/traceroute/portscan is performed on the host(s) given

-wh         - If this flag is selected the results will be printed out to a HTML page and opened in a browser

**Extra**

Though it was not required for the project I included checks for valid host and host range formats as well as valid port and port range formats. If the user makes a mistake in entering in the information then it will display an error message and exit the program without crashing.
