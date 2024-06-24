# automotive-security
Framework for black-box penetration testing of Electronic Control Unit, starting 
point of my Master Thesis in automotive cybersecurity @ AVL Italy. 

This tool aims at implementing several tests for ECU testing. 

Run: python3 main.py [--verbose] can_interface


The implemented tests are: 

- ISOTP-scanning
- Session scans
- Service enumerator
- Seed randomness evaluation
- Security Access interaction
- Fuzzing ...
- Read Data by Identifier
- etc. 
- etc. 
- etc. 


-----------------------------------------------------------------------------
Scapy is a powerful Python-based interactive packet manipulation program and
library. It can be used to forge or decode packets for a wide number of
protocols, send them on the wire, capture them, match requests and replies,
and much more. It is possible to load iso-tp kernel module 
https://github.com/hartkopp/can-isotp