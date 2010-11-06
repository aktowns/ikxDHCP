#!/usr/bin/env ruby
# 
# dhcpd.rb
#  
# Author:
#       Ashley Towns <ashleyis@me.com>
# 
# Copyright (c) 2010 Ashley Towns
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

require_relative 'shared'

raise "Please provide an interface to use via the command line (#{__FILE__} en1)" if ARGV[0].nil?
@eth = ARGV[0]
@mac = get_macaddr()[@eth]

def dhcp_discover
  send_packet :chaddr => @mac, :ethsrc => @mac, :dhcpoptions => build_options_pack([:DHCPMessageType, :len, :DHCPMessageTypeDiscover],
                                                                                   [:DHCPParameters, :len, :DHCPSubnetMask, 
                                                                                    :DHCPRouter, :DHCPDNS, :DHCPDomainName,
                                                                                    :DHCPDNSDomainSearchList, :DHCPProxyAutoDiscovery],
                                                                                   [:DHCPClientIdentifier, :len, 0x00, 0x00],
                                                                                   [:DHCPHostName, :len, str2hex("test")],
                                                                                   [DHCPOptionsEnd])
end
def dhcp_request 
  send_packet :chaddr => @mac, :ethsrc => @mac, :dhcpoptions => build_options_pack([:DHCPMessageType, :len, :DHCPMessageTypeRequest],
                                                                                   [:DHCPParameters, :len, :DHCPSubnetMask, 
                                                                                    :DHCPRouter, :DHCPDNS, :DHCPDomainName,
                                                                                    :DHCPDNSDomainSearchList, :DHCPProxyAutoDiscovery],
                                                                                   [:DHCPClientIdentifier, :len, DHCPHtype, to_primative_mac(@mac) ],
                                                                                   [:DHCPMaxDHCPMessageSize, :len, 0x05, 0xDC], # 1500
                                                                                   [:DHCPIPAddressLeaseTime, :len, 0x00, 0x01, 0x51, 0x80], # 1 Day
                                                                                   [:DHCPRequestedIPAddress, :len, to_primative_ip("192.168.1.3")], # 0.0.0.0
                                                                                   [:DHCPHostName, :len, str2hex("eeebox-arch")],
                                                                                   [DHCPOptionsEnd])
end
dhcp_discover
loop do 
  puts "Resending.."
  dhcp_request
  sleep 5
end
puts "Sleep loops"
sleep 100000