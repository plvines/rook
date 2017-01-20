# Rook
Rook is a covert communication system that works by hiding information in altered network data. 
It was designed with first-person shooters in mind, but can theoretically work on other applications.

## Packet Parsing Module
Rook is modular, the code here is the basic client and server framework. Both of these depend on a packet parsing module (a mock example is provided in DummyParsers and the Parser class is described in StegoEngine.py).
The parsing module takes a packet from the application and parses it to find _mutable fields_, which are selections of bits that can be altered by Rook without creating invalid application packets. Thus, to run Rook on a given protocol, you must create a packet parsing module to do this so that Rook will not accidentally overwrite structural data and create invalid packets.
