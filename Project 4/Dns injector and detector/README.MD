CSE508: Network Security, Fall 2017 
Homework 4: DNS Packet Injection 

Mihir Chakradeo - 111462188

--------------------------------------------------------------------------------------------- 
Part 1: dnsinject 
--------------------------------------------------------------------------------------------- 
 
I developed a dns packet injector in python which captures traffic from a network interface in promiscuous mode, and injects forged responses to selected DNS A requests with the goal to poison 
the resolver's cache. 

-Libraries used:  
	1. scapy – packet manipulation  
	2. argparse – parsing the command line arguments (-i, -h flags) 
	3. os – to run shell script to get default interface (when interface is not specified) 

-Testing Environment: 
	-Attacker: Ubuntu 16.04.3 LTS, Linux 4.10.0-37-generic x86_64 
	-Victim: (VM – Virtualbox) Ubuntu 17.10, Linux 4.13.0-16-generic x86_64 
	-Language: Python 2.7.12 
	
-Implementation Details: 
	In dnsinject(pkt), I am first checking if the incoming packet has IP header, DNS header and DNSQR. If present, then I 		check whether the domain name is present in hostnames.txt. If present then that means that we have to spoof the packet 		with the corresponding IP given in the hostnames.txt. Finally, to create a forged response, I have used scapy's built 		In methods to forge a packet and then injecting it using send() method. Changes in the header for spoofed packet: 
	-IP: destination will be the request's source, and source will be the request's destination 
	-UDP: destination port will become the request's source port, and source port will be the request's destination port 
	-DNS: id, qd remain the same. Rdata is where we put the spoofed ip retrieved from the hostfile or the attacker's IP 		(when hostfile not entered) 
 
 
-Execution Steps: 
	-Run following command on attacker's side: 
	$sudo python dnsinject.py -h hostnames.txt "udp port 53" 
	 
	Where expression = "udp port 53" 
 
	-At victim's side, run: 
	$dig <domain_name> 
	 
	Example: 
	dig @109.69.8.51 www.yandex.com 
	Here, @109.69.8.51 forces to use puntCAT's DNS server (as the requests are resolved slower compared to ISP's DNS) 
 
 
-Sample Output: 
 
	1. When Hostfile given 
 
 
	HOSTNAMES.TXT used for sample: 
	10.6.6.6      foo.example.com 
	10.6.6.6      bar.example.com 
	192.168.66.6  www.cs.stonybrook.edu 
	192.168.66.6 www.yandex.com 
	192.168.66.6 www.instagram.com 
 
 
	-ATTACKER'S SIDE: 
	 
		mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW4$ sudo python dnsinject.py -h hostnames.txt 			"udp port 53" 
		No interface specified 
		hostnames.txt 
		['udp port 53'] 
		Default Interface:  wlp3s0 
		  
		---------------Sniffed packet---------------- 
		10.255.35.87 -> 109.69.8.51 : www.yandex.com 
		. 
		Sent 1 packets. 
		DNS Ans "192.168.66.6"  
		 
	 
	-VICTIM'S SIDE: 
		ubuntu@ubuntu:~/Downloads$ dig @109.69.8.51 www.yandex.com 
		 
		; <<>> DiG 9.10.3-P4-Ubuntu <<>> @109.69.8.51 www.yandex.com 
		; (1 server found) 
		;; global options: +cmd 
		;; Got answer: 
		;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5658 
		;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0 
		;; WARNING: recursion requested but not available 
		 
		;; QUESTION SECTION: 
		;www.yandex.com.            IN    A 
		 
		;; ANSWER SECTION: 
		www.yandex.com.        10    IN    A    192.168.66.6 
		 
		;; Query time: 300 msec 
		;; SERVER: 109.69.8.51#53(109.69.8.51) 
		;; WHEN: Thu Dec 07 20:50:08 UTC 2017 
		;; MSG SIZE  rcvd: 62 
		 
	2. When Hostfile not given 
 
	-ATTACKER'S SIDE: 
		mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW4$ sudo python dnsinject.py "udp port 53" 
		No interface specified 
		['udp port 53'] 
		Default Interface:  wlp3s0 
		  
		---------------Sniffed packet---------------- 
		10.255.35.87 -> 109.69.8.51 : www.google.com 
		Host file not entered, spoof with local IP:  10.255.42.185 
		. 
		Sent 1 packets. 
		DNS Ans "10.255.42.185"  
 
 
	-VICTIM'S SIDE: 
		ubuntu@ubuntu:~/Downloads$ dig @109.69.8.51 www.google.com 
		 
		; <<>> DiG 9.10.3-P4-Ubuntu <<>> @109.69.8.51 www.google.com 
		; (1 server found) 
		;; global options: +cmd 
		;; Got answer: 
		;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22764 
		;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0 
		;; WARNING: recursion requested but not available 
		 
		;; QUESTION SECTION: 
		;www.google.com.            IN    A 
		 
		;; ANSWER SECTION: 
		www.google.com.        10    IN    A    10.255.42.185 
		 
		;; Query time: 61 msec 
		;; SERVER: 109.69.8.51#53(109.69.8.51) 
		;; WHEN: Thu Dec 07 21:02:07 UTC 2017 
		;; MSG SIZE  rcvd: 62 
 
--------------------------------------------------------------------------------------------- 
Part 2: dnsdetect 
--------------------------------------------------------------------------------------------- 
I developed a dns poisoning attack detector in python which captures traffic from a network interface in promiscuous mode, and detects dns poisoning attacks (as done in dnsinject). This program can detect live spoofing attempts as well as detect spoofing attempts which were done before (from a pcap capture file). 
 
Note: Expression (BPF filter) not working for offline (pcap) capture. It is a commonly known issue, and a problem in scapy.
 
-Libraries used:  
	1. scapy – packet manipulation  
	2. argparse – parsing the command line arguments (-i, -r flags) 
	3. os – to run shell script to get default interface (when interface is not specified) 
	4. time – to get the timestamp of the spoofed packet 
 
-Testing Environment: 
	-Attacker: (VM 1 – Virtualbox) Ubuntu 17.10, Linux 4.13.0-16-generic x86_64 
	-Victim: (VM 2 – Virtualbox) Ubuntu 17.10, Linux 4.13.0-16-generic x86_64 
	-Language: Python 2.7.12 
 
-Implementation Details: 
	First, I checked if the pcap file has been provided or not (-r flag). If a pcap file has been provided, then we have to 	do offline analysis, otherwise proceed getting the correct interface, and analyze on that. The idea used is that, 		spoofing has happened if two packets are received by the victim with the same TXID, same source IP, same source Port, 		but the response (IP) of the two packets do not match (rdata). If this is observed, then it means that poisoning 		attempt has been made.  
	Every packet received is stored in a python list. Every time a packet arrives, it gets compared with already received 		packets stored in the received list (on basis of ip, port, id, rdata). 
 
-Execution Steps: 
	1. Run dnsinject (part 1) at attacker's side (VM 1) to spoof the packets. 
	2. Run dnsdetect at victim's (VM 2) side. 
	3. Run a command like dig or nslookup at victim's side (VM 2). 
	 
	Sample: 
	-ATTACKER SIDE (VM 1): 
		Terminal 1 
		$sudo python dnsdetect.py 
		Terminal 2 
		$dig <domain> 
		Example: 
		dig @109.69.8.51 www.yandex.com 
		Here, @109.69.8.51 forces to use puntCAT's DNS server (as the requests are resolved slower compared to ISP's 			DNS)
		 
	-VICTIM SIDE (VM 2): 
		sudo python dnsinject.py 
 
 
-Sample Output: 
	1. Analysis of Live Capture 
		-VICTIM: 
			TERMINAL 1 
 
				ubuntu@ubuntu:~/Downloads/111462188_Chakradeo$ sudo python dnsdetect.py 
				No interface specified
				Default Interface:  enp0s3


				2017-12-09 05:18:19 DNS poisoning attempt
				TXID  2834   stackoverflow.com.
				Answer1  10.255.35.87
				Answer2  ['151.101.193.69', '151.101.1.69', '151.101.65.69', '151.101.129.69']


				2017-12-09 05:18:25 DNS poisoning attempt
				TXID  38047   facebook.com.
				Answer1  10.255.35.87
				Answer2  31.13.64.35
 
 
			TERMINAL 2 
				ubuntu@ubuntu:~/Downloads/111462188_Chakradeo$ dig @109.69.8.51 stackoverflow.com

				; <<>> DiG 9.10.3-P4-Ubuntu <<>> @109.69.8.51 stackoverflow.com
				; (1 server found)
				;; global options: +cmd
				;; Got answer:
				;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2834
				;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
				;; WARNING: recursion requested but not available

				;; QUESTION SECTION:
				;stackoverflow.com.        IN    A

				;; ANSWER SECTION:
				stackoverflow.com.    10    IN    A    10.255.35.87

				;; Query time: 164 msec
				;; SERVER: 109.69.8.51#53(109.69.8.51)
				;; WHEN: Sat Dec 09 05:18:19 UTC 2017
				;; MSG SIZE  rcvd: 68

				ubuntu@ubuntu:~/Downloads/111462188_Chakradeo$ dig @109.69.8.51 facebook.com

				; <<>> DiG 9.10.3-P4-Ubuntu <<>> @109.69.8.51 facebook.com
				; (1 server found)
				;; global options: +cmd
				;; Got answer:
				;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38047
				;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
				;; WARNING: recursion requested but not available

				;; QUESTION SECTION:
				;facebook.com.            IN    A

				;; ANSWER SECTION:
				facebook.com.        10    IN    A    10.255.35.87

				;; Query time: 6 msec
				;; SERVER: 109.69.8.51#53(109.69.8.51)
				;; WHEN: Sat Dec 09 05:18:25 UTC 2017
				;; MSG SIZE  rcvd: 58
 
		-ATTACKER: 
			 
			ubuntu@ubuntu:~/Downloads/111462188_Chakradeo$ sudo python dnsinject.py 
			No interface specified
			Default Interface:  enp0s3

			---------------Sniffed packet----------------
			10.255.42.54 -> 109.69.8.51 : www.stackoverflow.com
			Host file not entered, spoof with local IP:  10.255.35.87
			.
			Sent 1 packets.
			DNS Ans "10.255.35.87" 

			---------------Sniffed packet----------------
			10.255.42.54 -> 109.69.8.51 : www.facebook.com
			Host file not entered, spoof with local IP:  10.255.35.87
			.
			Sent 1 packets.
			DNS Ans "10.255.35.87" 

 
 
 
	2.Analysis of Pcap Capture File 
	
	-PCAP FILE: dns.pcap
	 
	-Output: 
		mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/111462188_HW4$ sudo python dnsdetect.py -r dns.pcap 
		No interface specified 
		dns.pcap 
		Analyzing tracefile 
		2017-12-07 01:05:45 DNS poisoning attempt 
		TXID  56344   www.yandex.com. 
		Answer1  213.180.204.62 
		Answer2  192.168.66.6 
		  
		2017-12-07 01:06:00 DNS poisoning attempt 
		TXID  38808   www.yandex.com. 
		Answer1  192.168.66.6 
		Answer2  213.180.204.62 
		  
		2017-12-07 01:06:16 DNS poisoning attempt 
		TXID  57597   www.instagram.com. 
		Answer1  192.168.66.6 
		Answer2  z-p42-instagram.c10r.facebook.com. 

-References

Part 1:
	https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
	https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
	https://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
	https://thepacketgeek.com/scapy-p-09-scapy-and-dns/
	https://www.ietf.org/rfc/rfc1035.txt
	
Part 2:
	https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
	https://unix.stackexchange.com/questions/14961/how-to-find-out-which-interface-am-i-using-for-connecting-to-the-internet
	https://stackoverflow.com/questions/12400256/converting-epoch-time-into-the-datetime
	
