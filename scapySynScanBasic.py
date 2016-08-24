#! /usr/bin/env python
from logging import getLogger, ERROR 
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import time

ip_addr = "192.168.1.2"
port = range(1, 1000)
s_port = 20

conf.verb = 0
conf.L3socket = L3RawSocket
print '[*] Beginning Scan'
t1=time.clock()
for p in port:
	s = IP(dst=ip_addr)/TCP(sport=s_port, dport=p, flags="S")
	snd = sr1(s, timeout=1)
	if str(type(snd)) == "<type 'NoneType'>":
		pass
	elif snd.haslayer(TCP):
		if snd.getlayer(TCP).flags == 0x12:
			r = IP(dst=ip_addr)/TCP(sport=s_port, dport=p, flags="R")
			rsnd = sr(r, timeout=2)
			print '%d open' % p
		elif snd.getlayer(TCP).flags == 0x14:
			pass
t2=time.clock()
print '[*] Scan Completed'
print '[*] Scanning took %f' % (t2-t1)
