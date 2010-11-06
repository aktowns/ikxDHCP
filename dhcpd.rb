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

# BUG: Not handling double 00 in xid properly.

PORT = 67

@ip_pool = lambda{pool = {}; (10..254).each{|x| pool["192.168.1.#{x}"] = false }; pool}.call

def first_free_ip
  @ip_pool.each {|x,y| return x if y == false}
  raise "IP Pool has been exhausted.."
end

def send_offer packet, options
  send_packet :op => 2, :xid => packet.xid,:chaddr => packet.chaddr, :ethsrc => @mac, :yiaddr => first_free_ip,# To give them what they want => :yiaddr => hex2ipstr(options[:DHCPRequestedIPAddress]),
  :saddr => '192.168.1.3', :sport => PORT, :dport => PORT+1, :dhcpoptions => build_options_pack(
    [:DHCPMessageType, :len, :DHCPMessageTypeOffer],
    [:DHCPServerIdentifier, :len, to_primative_ip('192.168.1.3')],
    [:DHCPIPAddressLeaseTime, :len, 0x00, 0x01, 0x51, 0x80], # 1 Day
    [:DHCPSubnetMask, :len, to_primative_ip('255.255.255.0')],
    [:DHCPRouter, :len, to_primative_ip('192.168.1.1')],
    [:DHCPDNS, :len, to_primative_ip('192.231.203.150'), to_primative_ip('192.231.203.151')],
    [:DHCPHostName, :len, str2hex("ikebookpro")],
    [DHCPOptionsEnd]
  )
end
def send_ack packet, options
  if (@ip_pool[hex2ipstr(options[:DHCPRequestedIPAddress])] == false)
    puts "Giving out #{hex2ipstr(options[:DHCPRequestedIPAddress])}"
    ip = hex2ipstr(options[:DHCPRequestedIPAddress])
    @ip_pool[ip] = true
  else
    puts "Giving out #{first_free_ip}"
    ip = first_free_ip
    @ip_pool[ip] = true
  end
  send_packet :op => 2, :xid => packet.xid,:chaddr => packet.chaddr, :ethsrc => @mac, :yiaddr => ip,  # To give them what they want => :yiaddr => hex2ipstr(options[:DHCPRequestedIPAddress]),
  :saddr => '192.168.1.3', :sport => PORT, :dport => PORT+1, :dhcpoptions => build_options_pack(
    [:DHCPMessageType, :len, :DHCPMessageTypeAck],
    [:DHCPServerIdentifier, :len, to_primative_ip('192.168.1.3')],
    [:DHCPIPAddressLeaseTime, :len, 0x00, 0x01, 0x51, 0x80], # 1 Day
    [:DHCPSubnetMask, :len, to_primative_ip('255.255.255.0')],
    [:DHCPRouter, :len, to_primative_ip('192.168.1.1')],
    [:DHCPDNS, :len, to_primative_ip('192.231.203.150'), to_primative_ip('192.231.203.151')],
    [:DHCPHostName, :len, str2hex("ikebookpro")],
    [DHCPOptionsEnd]
  )
  
end

def handle_packet packet
  #p packet
  return if packet == nil
  options = hex2dhcpops(packet.dhcpoptions)
  #p options
  case options[:DHCPMessageType]
    when :DHCPMessageTypeDiscover
      puts "[#{packet.xid}] Received a DHCPDiscover from #{hex2mac(packet.chaddr.to_binary_s)}"
      puts "[#{packet.xid}] Sending a DHCPOffer to #{hex2mac(packet.chaddr.to_binary_s)}"
      send_offer packet, options
    when :DHCPMessageTypeRequest
      puts "[#{packet.xid}] Received a DHCPRequest from #{hex2mac(packet.chaddr.to_binary_s)} (Hostname: #{options[:DHCPHostName].join})(Requesting: #{hex2ip(options[:DHCPRequestedIPAddress].join)})"
      if !options[:DHCPServerIdentifier].nil? && hex2ipstr(options[:DHCPServerIdentifier]) != "192.168.1.3"
        puts "* Request is not for us :(" 
        return
      end
      puts "* TODO: writelease file"
      puts "[#{packet.xid}] Sending a DHCPAck to #{options[:DHCPHostName].join} for #{first_free_ip}"
      send_ack packet, options
    else
      puts "I don't know of a #{options[:DHCPMessageType]}"
  end
end

BasicSocket.do_not_reverse_lookup = true
s = UDPSocket.new
s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
s.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, 1)
s.bind("", PORT)

puts "DHCPd active.."
loop do
  packet = s.recvfrom(1024)[0]
  handle_packet decompile_packet(packet)
end
s.close
