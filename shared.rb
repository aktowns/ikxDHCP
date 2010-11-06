# 
# shared.rb
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

require 'packetfu'
require 'bindata'
require 'socket'

DHCPPacketOP = 0x01
DHCPHtype = 0x01
DHCPHeaderLength = 0x06
DHCPHops = 0x0
DHCPMagicCookie = 0x63825363
DHCPOptionsEnd  = 0xFF
DHCPPacketXID = 0x34334390

# Based off http://en.wikipedia.org/wiki/DHCP
class DHCPPacket < BinData::Record
    endian :big
    bit8    :op
    bit8    :htype
    bit8    :hlen
    bit8    :hops
    bit32   :xid
    bit16   :secs
    bit16   :flags
    array   :ciaddr, :type => :bit8, :initial_length => 4
    array   :yiaddr, :type => :bit8, :initial_length => 4
    array   :siaddr, :type => :bit8, :initial_length => 4
    array   :giaddr, :type => :bit8, :initial_length => 4
    array   :chaddr, :type => :bit8, :initial_length => 16
    string  :sname, :length => 64
    string  :file,  :length => 128
    bit32   :isdhcp, :value => DHCPMagicCookie
    array   :dhcpoptions, :type => :bit8, :endian => :big # Should maybe add a limit.
end

DHCPOP_MESSAGETYPES = {
  # DHCP Message type responses (all len = 1)
  :DHCPMessageTypeDiscover          => 1,
  :DHCPMessageTypeOffer             => 2,
  :DHCPMessageTypeRequest           => 3,
  :DHCPMessageTypeDecline           => 4,
  :DHCPMessageTypeAck               => 5,
  :DHCPMessageTypeNak               => 6,
  :DHCPMessageTypeRelease           => 7,
}
DHCPOP_CONSTANTS = {
  # DHCP Options
  :DHCPPad                          => 0,
  :DHCPSubnetMask                   => 1,
  :DHCPTimeOffset                   => 2,
  :DHCPRouter                       => 3,
  :DHCPTimeServer                   => 4,
  :DHCPNameServer                   => 5,
  :DHCPDNS                          => 6,
  :DHCPLogServer                    => 7,
  :DHCPQuoteServer                  => 8,
  :DHCPLPRServer                    => 9,
  :DHCPImpressServer                => 10,
  :DHCPRLServer                     => 11,
  :DHCPHostName                     => 12,
  :DHCPBootFileSize                 => 13,
  :DHCPMeritDumpFile                => 14,
  :DHCPDomainName                   => 15,
  :DHCPSwapServer                   => 16,
  :DHCPRootPath                     => 17,
  :DHCPExtensionsPath               => 18,
  :DHCPIPForwarding                 => 19,
  :DHCPNonLocalRouting              => 20,
  :DHCPPolicyFilter                 => 21,
  :DHCPMaximumDRSize                => 22, # Datagram reassembly size
  :DHCPDefaultIPTTL                 => 23,
  :DHCPPathMTUAgingTimeout          => 24,
  :DHCPPathMTUPlateauTable          => 25,
  :DHCPInterfaceMTU                 => 26,
  :DHCPAllSubnetsLocal              => 27,
  :DHCPBroadcastAddress             => 28,
  :DHCPPerformMask                  => 29, # Perform mask discovery
  :DHCPMaskSupplier                 => 30, # Zelda flashbacks
  :DHCPPerformRouter                => 31, # Perform router discovery
  :DHCPRouterSolicitation           => 32, # Router Solicitation Address
  :DHCPStaticRoutingEnable          => 33,
  :DHCPTrailerEncap                 => 34, # Trailer Encapsulation
  :DHCPArpCacheTimeout              => 35, 
  :DHCPEthernetEncap                => 36, # ethernet encapsulation
  :DHCPDefaultTCPTTL                => 37,
  :DHCPTCPKeepAliveInt              => 38, # TCP Keepalive interval
  :DHCPTCPKeepAliveGB               => 39, # TCP Keepalive garbage
  :DHCPNISDomain                    => 40,
  :DHCPNISServer                    => 41,
  :DHCPNTPServers                   => 42,
  :DHCPVendorSpecificInfo           => 43,
  :DHCPNetBIOSNameServer            => 44,
  :DHCPNetBIOSDDS                   => 45,
  :DHCPNetBIOSNodeType              => 46,
  :DHCPNetBIOSScope                 => 47,
  :DHCPXWindowSystemFont            => 48, # XWindow Font server
  :DHCPXWindowSystemDM              => 49, # Xwindow System Display Server
  :DHCPRequestedIPAddress           => 50,
  :DHCPIPAddressLeaseTime           => 51,
  :DHCPOptionOverload               => 52,
  :DHCPMessageType                  => 53,
  :DHCPServerIdentifier             => 54,
  :DHCPParameters                   => 55,
  :DHCPMessage                      => 56,
  :DHCPMaxDHCPMessageSize           => 57,
  :DHCPRenewTimeValue               => 58,
  :DHCPRebindingTimeValue           => 59,
  :DHCPClassIdentifier              => 60,
  :DHCPClientIdentifier             => 61,
  :DHCPNetWareIPDomainName          => 62,
  :DHCPNetWareIPInformation         => 63,
  :DHCPNISDomain                    => 64,
  :DHCPNISServers                   => 65,
  :DHCPTFTPServerName               => 66,
  :DHCPBootFileName                 => 67,
  :DHCPMobileIPHomeAgent            => 68,
  :DHCPSMTPServer                   => 69,
  :DHCPPOPServer                    => 70,
  :DHCPNNTPServer                   => 71,
  :DHCPDefaultWWWServer             => 72,
  :DHCPDefaultFingerServer          => 73,
  :DHCPDefaultIRCServer             => 74,
  :DHCPStreetTalkServer             => 75,
  :DHCPStreetTalkDAS                => 76,
  :DHCPUserClassInformation         => 77,
  :DHCPSLPDirectoryAgent            => 78,
  :DHCPSLPServiceScope              => 79,
  :DHCPRapidCommit                  => 80,
  :DHCPFQDN                         => 81,
  :DHCPRelayAgentInformation        => 82,
  :DHCPInternetStorageNameService   => 83,
  # ??
  :DHCPNDSServers                   => 85,
  :DHCPNDSTreeName                  => 86,
  :DHCPNDSContext                   => 87,
  :DHCPBCMCSContDomainNameList      => 88,
  :DHCPBCMCSContIPV4AddressList     => 89,
  :DHCPAuthentication               => 90,
  :DHCPClientLastTransactTime       => 91,
  :DHCPAssociatedIP                 => 92,
  :DHCPClientSystemArchType         => 93,
  :DHCPClientNetworkInterfaceIdent  => 94,
  :DHCPLDAP                         => 95,
  # ??
  :DHCPClientMachineIdent           => 97,
  :DHCPOGUA                         => 98,
  # ??
  :DHCPAutonomousSystemNumber       => 109,
  # ??
  :DHCPNetInfoParentServerAddress   => 112,
  :DHCPNetInfoParentServerTag       => 113,
  :DHCPURL                          => 114,
  :DHCPAutoConfigure                => 116,
  :DHCPNameServiceSearch            => 117,
  :DHCPSubnetSelection              => 118,
  :DHCPDNSDomainSearchList          => 119,
  :DHCPSIPServers                   => 120,
  :DHCPClasslessStaticRoute         => 121,
  :DHCPCableLabsClientConfig        => 122,
  :DHCPGeoConf                      => 123,
  # ??
  :DHCPProxyAutoDiscovery           => 252
}

# Ugh really fucking hacky
def get_macaddr
  currentEth = currentAddr = nil; macaddrs = {}
  `ifconfig`.split("\n").map! do |line|
    maybeEth = line.match(/([a-z]+[0-9]+): .*/)
    currentEth = maybeEth[1].strip if !maybeEth.nil?
    maybeAddr = line.match(/ether ([0-9 A-Ea-e \:]+)/)
    currentAddr = maybeAddr[1].strip if !maybeAddr.nil?
    if currentEth != nil && currentAddr != nil
      macaddrs[currentEth] = currentAddr
      currentEth = currentAddr = nil
    end
  end
  macaddrs
end
def to_primative_ip(ip)
  ip.split(/\./).collect { |int| int.to_i }
end
def to_primative_mac_p(mac)
  padding = ':00:00:00:00:00:00:00:00:00:00'
  mac += padding
  to_primative_mac(mac)
end
def to_primative_mac(mac)
  mac.split(/[:\x2d\x2e\x20\x5f]+/).collect {|x| x.to_i(16)}
end
def str2hex(str)
  hexed = []
  str.each_char {|char| hexed << char.unpack('U').first }
  hexed
end
def hex2dec hex
  hexref = "0x"
  hex.each_byte {|x| hexref += x.to_s 16}
  eval hexref # Baha!
end
def hex2ary hex
  ary = []
  hex.each_byte {|x| ary << x }
  ary
end
def hex2mac hex
  mac = ""
  hex.each_byte {|x| mac += ":#{x.to_s(16)}" if x != 0 }
  mac[1..mac.length-1]
end
def hex2ip hex
  ip = ""
  hex.each_byte {|x| ip += ".#{x.to_i}"}
  ip[1..ip.length-1]
end
def hex2ipstr hex
  hex.map{|x| x.unpack('C').first }.join('.')
end
# Build an options packet in sta-eyell
def build_options_pack (*options)
  getr = lambda{|value| value = DHCPOP_CONSTANTS[value].nil? ? value : DHCPOP_CONSTANTS[value]; DHCPOP_MESSAGETYPES[value].nil? ? value : DHCPOP_MESSAGETYPES[value] }
  # Build the tree
  packets = options.map do |x|
    packet = []
    if x.class == Array
      x.each {|y| (y.class == Array ? y.each{|z| packet << getr.call(z)} : packet << getr.call(y))}
    else; raise "Packet option should be an array."; end
    packet
  end
  # Work out the lengths, out = length-(op+1)
  ret = []
  packets.each {|packet| packet.each {|obj| ret << (obj == :len ? packet.length-2 : obj)}}
  ret
end
def op2co op
  DHCPOP_CONSTANTS.each {|x,y| return x if y == op }
  raise "Fatal: OP Error #{op} is not known."
  return op.chr
end
def hex2dhcpops hex
  getr = lambda{|value| DHCPOP_CONSTANTS[value].nil? ? value : DHCPOP_CONSTANTS[value]}
  options = []
  sgrab = hex[2]
  i = 2
  while i < hex.length
    opcode = hex[i-2]
    length = hex[i-1]
    opts   = hex[i..length+i-1]
    options << [opcode, opts]
    i = i+length+2
  end
  options.map! do |x|
    x.map! do |y|
      if y.class == Array
        if x[0] == :DHCPMessageType
          DHCPOP_MESSAGETYPES.detect {|na,va| va == y.first }[0]
        elsif x[0] == :DHCPParameters
          y.map!{|z| op2co(z)}
        else
          y.map!{|z| z.chr }
        end
      else
        break if y == 255 # end
        op2co(y) 
      end
    end
  end
  ret = {}
  options.each do |option|
    next if option == nil
    next if option == :DHCPPad
    ret[option.first] = option[1..option.length].first
  end
  ret
end
def decompile_packet packet
  current_packet = DHCPPacket.new
  # DHCP Packet decompile
  current_packet.op           = hex2dec(packet[0])                  # 8bit  
  current_packet.htype        = hex2dec(packet[1])                  # 8bit  
  current_packet.hlen         = hex2dec(packet[2])                  # 8bit  
  current_packet.hops         = hex2dec(packet[3])                  # 8bit  
  current_packet.xid          = hex2dec(packet[4..7])               # 32bit 
  current_packet.secs         = hex2dec(packet[8..9])               # 16bit 
  current_packet.flags        = hex2dec(packet[10..11])             # 16bit
  current_packet.ciaddr       = hex2ary(packet[12..15])             # 32bit (ary)
  current_packet.yiaddr       = hex2ary(packet[16..19])             # 32bit (ary)
  current_packet.siaddr       = hex2ary(packet[20..23])             # 32bit (ary)
  current_packet.giaddr       = hex2ary(packet[24..27])             # 32bit (ary)
  current_packet.chaddr       = hex2ary(packet[28..43])             # 128bit (ary)
  current_packet.sname        = packet[44..107]                     # 64bit (str)
  current_packet.file         = packet[108..235]                    # 128bit (str)
  magic_cookie                = hex2dec(packet[236..239])           # COOKIEZ OMNOMNOM (32bit)
  current_packet.dhcpoptions  = hex2ary(packet[240..packet.length]) # DHCP Options (rest)
  return nil if magic_cookie != DHCPMagicCookie
  return current_packet
end
def send_packet(options = {})
  # Sane defaults
  src_p  = options[:sport].nil?  ? 68 : options[:sport]
  dst_p  = options[:dport].nil?  ? 67 : options[:dport]
  src_a  = options[:saddr].nil?  ? '0.0.0.0' : options[:saddr]
  dst_a  = options[:daddr].nil?  ? '255.255.255.255' : options[:daddr]
  ethsrc = options[:ethsrc].nil? ? 'ff:ff:ff:ff:ff:ff' : options[:ethsrc]
  ethdst = options[:ethdst].nil? ? 'ff:ff:ff:ff:ff:ff' : options[:ethdst]
  op     = options[:op].nil?     ? DHCPPacketOP : options[:op]
  htype  = options[:htype].nil?  ? DHCPHtype : options[:htype]
  hlen   = options[:hlen].nil?   ? DHCPHeaderLength : options[:hlen]
  hops   = options[:hops].nil?   ? DHCPHops : options[:hops]
  xid    = options[:xid].nil?    ? DHCPPacketXID : options[:xid]
  ciaddr = options[:ciaddr].nil? ? '0.0.0.0' : options[:ciaddr]
  yiaddr = options[:yiaddr].nil? ? '0.0.0.0' : options[:yiaddr]
  siaddr = options[:siaddr].nil? ? '0.0.0.0' : options[:siaddr]
  giaddr = options[:giaddr].nil? ? '0.0.0.0' : options[:giaddr]
  chaddr = options[:chaddr].nil? ? "ff:ff:ff:ff:ff:ff" : options[:chaddr]
  sname  = options[:sname].nil?  ? "" : options[:sname]
  file   = options[:file].nil?   ? "" : options[:file]
  dhcpoptions = options[:dhcpoptions].nil? ? [nil] : options[:dhcpoptions]
  # Build the dhcp packet
  dhcppacket             = DHCPPacket.new
  dhcppacket.op          = op
  dhcppacket.htype       = htype
  dhcppacket.hlen        = hlen
  dhcppacket.hops        = hops
  dhcppacket.xid         = xid
  dhcppacket.ciaddr      = (ciaddr.class == Array ? ciaddr : to_primative_ip(ciaddr))
  dhcppacket.yiaddr      = (yiaddr.class == Array ? yiaddr : to_primative_ip(yiaddr))
  dhcppacket.siaddr      = (siaddr.class == Array ? siaddr : to_primative_ip(siaddr))
  dhcppacket.giaddr      = (giaddr.class == Array ? giaddr : to_primative_ip(giaddr))
  dhcppacket.chaddr      = (chaddr.class == BinData::Array ? chaddr : to_primative_mac_p(chaddr))
  dhcppacket.sname       = sname
  dhcppacket.file        = file
  dhcppacket.dhcpoptions = dhcpoptions
  # Build the UDP packet
  udppacket              = PacketFu::UDPPacket.new
  udppacket.udp_src      = src_p
  udppacket.udp_dst      = dst_p
  udppacket.ip_saddr     = src_a
  udppacket.ip_daddr     = dst_a
  udppacket.payload      = dhcppacket.to_binary_s
  udppacket.eth_header.eth_saddr = ethsrc
  udppacket.eth_header.eth_daddr = ethdst
  udppacket.recalc
  puts "src: #{src_p} dst: #{dst_p} src_a: #{src_a} dst_a: #{dst_a} eth_src: #{ethsrc} eth_dst: #{ethdst}"
  udppacket.to_w('en1')
end