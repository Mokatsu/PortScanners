#!/usr/bin/env python
#!python2
# -*- coding: utf-8 -*-
#
#  portscanner.py
#  
#  Copyright 2016 mokatsu <mokatsu@kali>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
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
#################
# Main Function #
def Start_Program():
	print '[*] Initializing Scan on HOST: %s (type= %s, protocol= %s)' %(args.HOST, args.flag, args.protocol)
	print '-----------------------------------------------------'
	time_1 = time.time()
	check_IP(args.HOST)
	time_2 = time.time()
	m, s = divmod(time_2 - time_1, 60)
	h, m = divmod(m, 60)
	print '-----------------------------------------------------'
	print '[*] Total ports scanned: %s in %d:%02d:%02d' %(len(result_list), h, m, s)
###############################
# check if IP Address is real #
def check_IP(HOST):
	try:
		socket.inet_aton(HOST)
		ICMP_scan()
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
############################
# Result for Pool function #
def log_results(result):
	result_list.append(result)
############################
# Port notifying functions #
def port_open(port):
	try:
		print '[*] %s		Open				%s' % (port, socket.getservbyport(port))
	except:
		print '[*] %s		Open				Unknown' % (port)

def port_open_filtered(port):
	try:
		print '[*] %s		Open/Filtered			%s' % (port, socket.getservbyport(port))
	except:
		print '[*] %s		Open				Unknown' % (port)

def port_filtered(port):
	try:
		print '[*] %s		Filtered Unknown		%s' % (port, socket.getservbyport(port))
	except:
		print '[*] %s		Open				Unknown' % (port)

def host_up():
	print '[*] HOST %s is alive' %(args.HOST)
	print '-----------------------------------------------------'

def host_down():
	print '[*] HOST %s is dead' %(args.HOST)
	print '[*] Exiting'
	exit(0)

def host_blocking_scan():
	print '[*] HOST %s is blocking scan' %(args.HOST)
	print '[*] Exiting, You can still try a port scan'
	exit(0)

def fw_on(port):
	try:
		print '[*] %s		Stateful			%s' % (port, socket.getservbyport(port))
	except:
		print '[*] %s		Stateful			Unknown' % (port)
################################
# Function for multiprocessing #
def multi_proc():
	print 'Port #		Port Opened		Port Service'
	pool = mp.Pool(processes=mp.cpu_count()*args.speed)
	try:
		for ptype in args.protocol:
			if ptype == 'TCP':
				for f in args.flag:
					for port in args.ports:
						pool.apply_async(TCP_scans, args = (port, f), callback = log_results)
			elif ptype == 'UDP':
				print 'pass2'
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
#############
# ping scan #
def ICMP_scan():
	packet = IP(dst=args.HOST)/ICMP()
	snd_packet = sr1(packet, timeout = 2)
	if str(type(snd_packet)) == "<type 'NoneType'>":
		host_down()
	elif int(snd_packet.getlayer(ICMP).type) == 3 and int(snp_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]:
		host_blocking_scan()
	else:
		host_up()
############
# TCP scan #
def TCP_scans(port, f):
	try:
		if f == 'N':
			f = ''
		elif f == 'W':
			f = 'A'
		packet = IP(dst=args.HOST)/TCP(flags=f, dport=port, sport=args.origin)
		snd_packet = sr1(packet, timeout=2)
		if str(type(snd_packet)) == "<type 'NoneType'>":
			if f == 'W':
				print 'No Response'
			elif f == 'A':
				fw_on(port)
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
			elif snd_packet.getlayer(TCP).flags == 0x04:
				pass
			elif snd_packet.haslayer(ICMP):
				if int(snd_packet.getlayer(ICMP).type) == 3 and int(snp_packet.getlayer(ICMP).code) in [1,2,3,9,10,13]:
					if f == 'A':
						fw_on(port)
					else:
						port_filtered(port)
	except Exception, e:
		print e
###########################################
# reply packet function for scans S and C #
def reply_packet(port, f):
	reply_packet = IP(dst=args.HOST)/TCP(flags=f, dport=port, sport=args.origin)
	replysnd_packet = sr(reply_packet, timeout=1)
	port_open(port)
########################
# removes scapy output #
conf.verb = 0
conf.L3socket = L3RawSocket
######################
#### Main Program ####
if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		prog='portScanner',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=('''\
		Command Line port scanner using the python language
		''')
		)
	parser.add_argument('HOST', help='Target HOST IP Address (required)', type=str, action='store')
	parser.add_argument('-P','--protocol-type', help='Select protocol [TCP, UDP] (required)', required=True, dest='protocol',  type=str, choices=['TCP','UDP'], nargs='*')
	parser.add_argument('-f', '--flags', help='Specify the type of scan (SYN=S, FIN=F, etc.)', dest='flag', default=['C'], type=str, choices=['A','C','S','F','N','W'], nargs='*')
	parser.add_argument('-p', '--ports', help='Port number(s) to be scanned on target HOST (default ports are: 1-1024)', dest='ports', default=range(1, 1025), nargs='*', type=int)
	parser.add_argument('-o', '--origin-port', help='Source port of where the packet is coming from', dest='origin', default=11790,  action='store', type=int)
	parser.add_argument('--speed', help='Process variable (number of Processes, default is 3)', dest='speed', default=3, action='store', type=int)
	parser.add_argument('-v', '--verbose', help='Verbosity level', action='count')
	parser.add_argument('--version', action='version', version='%(prog)s 0.1')
	args = parser.parse_args()
#######################
# First Function Call #
	Start_Program()
