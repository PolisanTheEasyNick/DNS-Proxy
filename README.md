# DNS-Proxy
It's a DNS Resolver with ability to blacklist unwanted queries.  
In config.conf file you can specify which queries to block and which status to return.  
Note: root access needed for port 52 binding.  

# Prerequisites 
libconfig library

# Building and running
```bash
$ make
$ sudo ./DNS-Proxy
```
