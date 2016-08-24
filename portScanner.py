#!/usr/bin/env python

# -*- coding: utf-8 -*-
#  portscanner.py

#  Copyright 2016 mokatsu <mokatsu@kali>

#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.

#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.


from logging import getLogger, ERROR 
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import argparse
import multiprocessing as mp
import time
import socket


"""List of Arguments"""
result_list = []

"""Program Functions"""

def Start_Program():
	print '[*] Initializing Scan (type= %s, protocol= %s)' %(args.flag, args.protocol)
	print '-----------------------------------------------------'
	print 'Port #		Port Opened		Port Service'
	print '-----------------------------------------------------'
	time_1 = time.time()
	check_IP(args.HOST)
	time_2 = time.time()
	print '-----------------------------------------------------'
	print '[*] Total ports scanned: %s in %s' %(len(result_list), time_2 - time_1)

# check if IP Address is real
def check_IP(HOST):
	try:
		socket.inet_aton(HOST)
		multi_proc()
	except socket.error:
		print '\n[*] Not an IP Address\n'
		parser.parse_args(['-h'])
		exit(0)
	except KeyboardInterrupt:
		pool.terminate()
		pool.join()
		print '\n[*] You terminated the scan'
		parser.parse_args(['-h'])
		exit(0)

def log_results(result):
	result_list.append(result)

def port_open(port):
	print '[*] %s			Open			%s' % (port, socket.getservbyport(port))

def port_open_filtered(port):
	print '[*] %s		Open/Filtered		Unknown' % (port)

def port_filtered(port):
	print '[*] %s		Filtered Unknown		Unknown' % (port)

def multi_proc():
	pool = mp.Pool(processes=mp.cpu_count()*args.speed)
	try:
		if args.protocol == 'TCP':
			for port in args.ports:
				for f in args.flag:
					pool.apply_async(TCP_scans, args = (port, f), callback = log_results)
		elif args.protocol == 'UDP':
			print 'pass2'
		elif args.protocol == 'ICMP':
			print 'pass3'
		pool.close()
		pool.join()
	except KeyboardInterrupt:
		pool.terminate()
		pool.join()
		print '\n[*] You terminated the scan'
		parser.parse_args(['-h'])
		exit(0)
	except Exception, e:
		print e
		pool.close()
		pool.join()

def TCP_scans(port, f):
	try:
		if f == 'N':
			f = ''
		elif f == 'W':
			f = 'A'
		packet = IP(dst=args.HOST)/TCP(flags=f, dport=port, sport=args.origin)
		snd_packet = sr1(packet, timeout=1)
		if str(type(snd_packet)) == "<type 'NoneType'>":
			if f == 'W':
				print 'No Response'
			else:
				port_open_filtered(port)
		elif snd_packet.haslayer(TCP):
			if snd_packet.getlayer(TCP).flags == 0x14:
				pass
			elif snd_packet.getlayer(TCP).flags == 0x12:
				if f == 'C':
					f = 'AR'
					reply_packet(port, f)
				elif f == 'S':
					f = 'R'
					reply_packet(port, f)
				elif packet.getlayer(TCP).window == 0:
					pass
				elif packet.getlayer(TCP).window > 0:
					port_open(port)
			elif snd_packet.haslayer(ICMP):
				if int(snd_packet.getlayer(ICMP).type) == 3 and int(snp_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]:
					port_filtered(port)
	except Exception, e:
		print e

def reply_packet(port, f):
	reply_packet = IP(dst=args.HOST)/TCP(flags=f, dport=port, sport=args.origin)
	replysnd_packet = sr(reply_packet, timeout=1)
	port_open()

conf.verb = 0
conf.L3socket = L3RawSocket

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		prog='portScanner',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=('''\
		Command Line port scanner using the python language
		''')
		)
	parser.add_argument('HOST', help='Target HOST IP Address (required)', type=str, action='store')
	parser.add_argument('-P','--protocol-type', help='Select protocol [ICMP, TCP, UDP] (required)', required=True, dest='protocol',  type=str, action='store')
	parser.add_argument('-f', '--flags', help='Specify the type of scan (SYN=S, FIN=F, etc.)', dest='flag', default=['C'], type=str, choices=['C','S','F','N','W'], nargs='*')
	parser.add_argument('-p', '--ports', help='Port number(s) to be scanned on target HOST (default ports are: 1-1024)', dest='ports', default=range(1, 1025), nargs='*', type=int)
	parser.add_argument('-o', '--origin-port', help='Source port of where the packet is coming from', dest='origin', default=11790,  action='store', type=int)
	parser.add_argument('--speed', help='Process variable (number of Processes, default is 3)', dest='speed', default=3, action='store', type=int)
	parser.add_argument('-v', '--verbose', help='Verbosity level', action='count')
	parser.add_argument('--version', action='version', version='%(prog)s 0.1')
	args = parser.parse_args()

	Start_Program()


