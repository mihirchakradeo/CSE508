import argparse
from scapy.all import *
import sys
import os
import time

global tracefile
global expression
global interface
global received
received = list()
global hflag

#cite: https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
def dnsdetect(pkt):
    global tracefile
    global expression
    global interface
    global received
    global hflag

    # if hflag == 1:
    #     pkt = rdpcap(tracefile)

    if IP in pkt:

        #getting default interface if -i flag not given
		#cite: https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
        if not interface and hflag == 0:
            interface = os.popen("route | grep '^default' | grep -o '[^ ]*$'").read().split()[0]
            print "Default Interface: ",interface
            print

        if pkt.haslayer(DNSRR) and pkt.haslayer(UDP):
            if len(received) > 0:
                for oldPacket in received:
                    #print oldPacket[DNS].id
                    if pkt[DNS].id == oldPacket[DNS].id \
                    and pkt[UDP].sport == oldPacket[UDP].sport and pkt[UDP].dport == oldPacket[UDP].dport \
                    and pkt[IP].dst == oldPacket[IP].dst \
                    and pkt[DNSRR].rdata != oldPacket[DNSRR].rdata:
                    	#cite: https://stackoverflow.com/questions/12400256/converting-epoch-time-into-the-datetime

                    	timeStamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(oldPacket.time))
                        print
                        anflag = 0
                        answer2 = list()
                        print timeStamp, "DNS poisoning attempt"
                        print "TXID ", oldPacket[DNS].id, " ", oldPacket[DNS].qd.qname
                        print "Answer1 ", oldPacket[DNSRR].rdata

                        if pkt[DNS].ancount > 1:
                            for i in range(pkt[DNS].ancount):
                                answer2.append(pkt[DNSRR][i].rdata)
                                anflag = 1
                        if anflag == 1:
                            print "Answer2 ", answer2
                        else:
                            print "Answer2 ", pkt[DNSRR].rdata
                        print

            #add info about packet to received list
            received.append(pkt)




def argumentParsing():
	parser = argparse.ArgumentParser(add_help = False, description = "dnsdetect [-i interface] [-r tracefile] expression")
	parser.add_argument("-i", metavar="interface")
	parser.add_argument("-r", metavar="tracefile")
	parser.add_argument('expression', nargs='*',action="store")
	args = parser.parse_args()
	return args.i, args.r, args.expression

if __name__ == '__main__':
    global tracefile
    global expression
    global interface
    global hflag
    iflag = 0
    hflag = 0
    eflag = 0

    interface, tracefile, expression = argumentParsing()

    if interface:
        print interface
        iflag = 1

    else:
        print "No interface specified"
        iflag = 0

    if tracefile:
        print tracefile
        hflag = 1

    if expression:
        eflag = 1
        expression = expression[0]
        print expression

    if eflag == 0:
        expression = "udp port 53"

    #either live capture or from pcap file
    if iflag == 1 and hflag == 1:
        print "Error, too many arguments"
        print "Usage: dnsdetect [-i interface] [-r tracefile] expression"
        sys.exit(0)

    #check if live capture or pcap file given
    if hflag == 1:
        #offline analysis
        print "Analyzing tracefile"
        sniff(offline = tracefile, filter = expression, prn = dnsdetect, store = 0)

    else:
        #live analysis
        #check for interface
        if iflag == 1:
            sniff(iface = interface, filter = expression, prn = dnsdetect, store = 0)
    	else:
    		sniff(filter = expression, prn = dnsdetect, store = 0)
