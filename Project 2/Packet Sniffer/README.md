Network Security HW 2 Report

This assignment involved developing a passive network monitoring application using libpcap in C++.
The program can handle live traffic as well as offline traffic (pcap capture files).
We can apply BPF filters to filter traffic (udp, tcp, icmp) by passing the filter name as an argument.
We can match a particular expression in the packet's payload by using the -s argument and providing the string which we want to match.

Made use of following helper functions:
	1. getopt() - to get command line argument arguments
	2. strstr() - to find the string entered from -s argument with the payload

I got the different headers using:
	ethernet header : X
	ip_header : X + Size_Ethernet
	tcp_header : X + Size_Ethernet + IP_Header_Length
	payload : X + Size_Ethernet + IP_Header_Length + TCP_Header_Length
	
Usage: sudo ./mydump [BPF_Filter] [-i interface] [-r read from file] [-s expression]

Sample output:
1. Live Capture
	mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/HW2$ sudo ./mydump 
	Device: wlp3s0

	2017-10-13 23:36:34.727142  7c:67:a2:5b:e5:fa -> 7c:67:a2:5b:e5:fa type 8 len 98
	172.24.20.46 -> 172.24.20.46 ICMP
	00000   42 86 e1 59 00 00 00 00  48 18 0b 00 00 00 00 00    B..Y....H.......
	00016   10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f    ................
	00032   20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f     !"#$%&'()*+,-./
	00048   30 31 32 33 34 35 36 37                             01234567

2. Offline Capture
	mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/HW2$ sudo ./mydump -r "hw1.pcap" | head
	Device: wlp3s0

	2013-01-12 11:37:42.871346  c4:3d:c7:17:6f:9b -> c4:3d:c7:17:6f:9b type 608 len 60
	111.155.192.168 -> 111.155.192.168 OTHER

	2013-01-12 11:38:02.227995  c4:3d:c7:17:6f:9b -> c4:3d:c7:17:6f:9b type 8 len 342
	192.168.0.1:20047 -> 192.168.0.1:21577 UDP
	00000   4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.
	00016   31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255
	00032   2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C

3. Filter Example
	mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/HW2$ sudo ./mydump -r "hw1.pcap" icmp
	Device: wlp3s0

	2013-01-14 12:42:31.752299  c4:3d:c7:17:6f:9b -> c4:3d:c7:17:6f:9b type 8 len 90
	1.234.31.20 -> 1.234.31.20 ICMP
	00000   45 00 00 30 00 00 40 00  2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....
	00016   01 ea 1f 14 00 50 7b 81  bd cd 09 c6 3a 35 22 b0    .....P{.....:5".
	00032   70 12 39 08 11 ab 00 00  02 04 05 b4 01 01 04 02    p.9.............

	Capture complete.
	
4. String search example
	mihir@mihir-Inspiron-15-7000-Gaming:~/Desktop/NetSec/HW2$ sudo ./mydump -r "hw1.pcap" -s "http" | head
	Device: wlp3s0

	2013-01-12 11:37:42.871346  c4:3d:c7:17:6f:9b -> c4:3d:c7:17:6f:9b type 608 len 60
	111.155.192.168 -> 111.155.192.168 OTHER
	http://192.168.0.1:80/RootDevice.xml
	NT: uuid:upnp-InternetGatewayDevice-1_0-c43dc7176f9b
	USN: uuid:upnp-InternetGatewayDevice-1_0-c43dc7176f9b
	NTS: ssdp:alive
	Server: UPnP/1.0 UPnP/1.0 UPnP-Device-Host/1.0


References:
	1. http://www.tcpdump.org/sniffex.c
	2. https://stackoverflow.com/questions/997512/string-representation-of-time-t
