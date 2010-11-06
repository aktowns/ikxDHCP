What Why?
---------------
This is just a way for me to learn the DHCP protocol abit better :)  
The server hands out ips fine, and replies to discover requests.  
At the moment the ip pool is hardcoded to (192.168.1.10+) and the router is hardcoded to 192.168.1.1 although both are easily changed.  

Requirements
----------------
Ruby --v=1.9


To use you need: 

* packetfu (gem install packetfu)
* bindata (gem install bindata)

To install you need ruby 1.9.x  
then launch with 
    './dhcp[dc].rb <eth adapter>'  

Released under the MIT license. 

[Website](http://aktowns.github.com/ikxDHCP/)
