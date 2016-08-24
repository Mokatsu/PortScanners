#! /usr/bin/env python
from logging import getLogger, ERROR 
getLogger("scapy.runtime").setLevel(ERROR) # takes out the error from scapy
from scapy.all import * # the packet creation module bases on python
import multiprocessing as mp # module for multiprocessing, to speed up the program
import time # timer

# basic global variables
ip_addr = raw_input("Enter the IP you wish to scan: \n")
s = int(raw_input("Enter your starting port: \n"))
e = int(raw_input("Enter your ending port: \n")) + 1
ports = range(s, e)
s_port = 20

# out main function that creates a packet and sends it, then checks for response
def scan(port):
	s = IP(dst=ip_addr)/TCP(sport=s_port, dport=port, flags="S") # creates packet ("S")
	snd = sr1(s, timeout=2) # sends packet
	if str(type(snd)) == "<type 'NoneType'>": 
		pass
	elif snd.haslayer(TCP): # checks the layer of the response from server
		if snd.getlayer(TCP).flags == 0x12:
			r = IP(dst=ip_addr)/TCP(sport=s_port, dport=port, flags="R")
			rsnd = sr(r, timeout=2) # closes the connection
			print '[*] Port %d is open' % port
		elif snd.getlayer(TCP).flags == 0x14:
			pass # checks for rst packet
	
# main program 
if __name__ == '__main__':
	conf.verb = 0 # removes scapy out put
	conf.L3socket = L3RawSocket # creates raw packet at lvl 3,needs root permission
	print '[*] Initialzing Scan...'
	time_1 = time.time() # starts timer
	pool = mp.Pool(processes=mp.cpu_count()*12) # multi process variable
	results = [pool.apply_async(scan, (port,))for port in ports] # takes results from the processors
	out = [r.get() for r in results] # places all results in variable
	time_2 = time.time() # ending timer
	tport = len(out)
	print '[*] Scan was completed on host %s in %f seconds' % (ip_addr, time_2-time_1)
	print '[*] Total of %d ports was scanned' % tport # counts number or processors/ports scanned
	exit() # exits program

# not part of the program
# since i am a beginner in python, there is no way I could had wrote this program by myself
# so here I will include all my sources that I had used during my research to write this program
# my way of saying, I give credit where credit is due

# Works Cited

# https://theitgeekchronicles.files.workpress.com/2012/05/scapyguide1.pdf
# This is the main book i read to learn how to use scapy to create packets and its basic syntax

# https://securitylair.wordpress.com/2014/02/21/simple-port-scanner-in-python-with-scapy-2/
# most of my main code is based on his, I tried to branch off as much as possible but that proved to be more difficult 

# http://stackoverflow.com/questions/7370801/measure-time-elapsed-in-python
# this post helped me set up my timer, to measure the elapsed time of the excecution

# https://doc.python.org/2/library/multiprocessing.html
# main doc for multiprocessing

# http://sebastianraschka.com/Articles/2014_multiprocessing_intro.html
# my main source of how I got my multiprocessing working, as an example I tried the example code from my main pythong function
# but that kept giving me major errors, so I used raschka's pool example code and adjusted it into mine

# http://www.secdev.org/projects/scapy/doc/usage/html
# some more scapy examples
