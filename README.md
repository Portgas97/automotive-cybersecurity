# automotive-security
Framework for black-box penetration testing of Electronic Control Unit, written for 
my Master's Thesis in automotive cybersecurity @ AVL Italy in collaboration with the 
University of Pisa. 

This tool aims to implement several ECU tests. 

Run: python3 main.py [--verbose] can_interface


The implemented tests are: 

- ISO-TP scanning
- Discover available diagnostic sessions
- Reset ECU testing
- TP format evaluation
- Seed randomness evaluation
- Security Access interaction
- Read Data by Identifier scan and selective reading
- Perform Write Data by Identifier
- Get and set the current session in the ECU server
- Request Upload
- Developing: read data by address, fuzzing, read sensitive scaling data, 


-----------------------------------------------------------------------------
The tool exploits Scapy, a powerful Python-based library.
It can be used to forge or decode packets for a wide number of
protocols, send them on the wire, capture them, match requests and replies,
and much more. It is possible to load iso-tp kernel module 
https://github.com/hartkopp/can-isotp
