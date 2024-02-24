# DNS-Proxy
It's a DNS Resolver with ability to blacklist unwanted queries.  
In config.conf file you can specify which queries to block and which status to return.  
Note: root access needed for port 52 binding.  

# Prerequisites 
libconfig library

# Building and running
```bash
$ cmake .
$ make
$ sudo ./DNS-Proxy
```
# Testing
You can test Proxy work using program like dnslookup:
```
$ dnslookup github.com 127.0.0.1
```
It will send single query response to our DNS server and, if succeed, receive DNS Response with github.com IP.

Also you can see speed of DNS server using dnsperf:
```
$ dnsperf -s 127.0.0.1 -d test-list.txt
```
It will send many Queries Per Second to our local server from test-list.txt list with queries.  
Also you can set 127.0.0.1 as your system DNS resolver in /etc/resolv.conf. 
