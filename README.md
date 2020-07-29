- #Apply these settings via IPTABLES

##Block Invalid Packets
- iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
This rule blocks all packets that are not a SYN packet and don’t belong to an established TCP connection.

##Block New Packets That Are Not SYN
- iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
This blocks all packets that are new (don’t belong to an established connection) and don’t use the SYN flag. 

##Block Uncommon MSS Values
- iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
- The above iptables rule blocks new packets (only SYN packets can be new packets as per the two previous rules) that use a TCP MSS value that is not common. 
 
##Block Packets With Fake TCP Flags
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
- iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
The above ruleset blocks packets that use Fake TCP flags, ie. TCP flags that legitimate packets wouldn’t use.’

##Block Packets From Private Subnets (Spoofing)
- iptables -t mangle -A PREROUTING -s 224.0.0.0/3 -j DROP 
- iptables -t mangle -A PREROUTING -s 169.254.0.0/16 -j DROP 
- iptables -t mangle -A PREROUTING -s 172.16.0.0/12 -j DROP 
- iptables -t mangle -A PREROUTING -s 192.0.2.0/24 -j DROP 
- iptables -t mangle -A PREROUTING -s 192.168.0.0/16 -j DROP 
- iptables -t mangle -A PREROUTING -s 10.0.0.0/8 -j DROP 
- iptables -t mangle -A PREROUTING -s 0.0.0.0/8 -j DROP 
- iptables -t mangle -A PREROUTING -s 240.0.0.0/5 -j DROP 
- iptables -t mangle -A PREROUTING -s 127.0.0.0/8 ! -i lo -j DROP
 
##Additional Rules
- iptables -t mangle -A PREROUTING -p icmp -j DROP
This drops all ICMP packets. 

- iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset
This iptables rule helps against connection attacks. It rejects connections from hosts that have more than 80 established connections. 

- iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 60/s --limit-burst 20 -j ACCEPT 
- iptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP
Limits the new TCP connections that a client can establish per second. 

- iptables -t mangle -A PREROUTING -f -j DROP
This rule blocks fragmented packets. ]

- iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s --limit-burst 2 -j ACCEPT 
- iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
 
##SSH Bruteforce
- iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
- iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

##Protection against port scanning
- iptables -N port-scanning 
- iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
- iptables -A port-scanning -j DROP# iptable-ddos-rules