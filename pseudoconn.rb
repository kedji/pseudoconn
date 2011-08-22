#!/usr/bin/env ruby

# This class provides a simple scripting interface to simulating client/server
# network traffic over TCP or UDP.

require 'ipaddr'

class PseudoConn

  # This class holds everything necessary to manage a single TCP or UDP
  # connection over IPv4 or IPv6.
  class Connection

    DEFAULTS = { :transport => :tcp, :ack => false, :mtu => 1500,
                 :src_port => nil, :src_seq => 0x0FFFFFFF,
                 :dst_port => 1025, :dst_seq => 0x7FFFFFFF, :ipv6 => false,
                 :src_mac => "AA\0\0BB", :dst_mac => "CC\0\0DD",
                 :src_ip => "10.0.0.1", :dst_ip => "42.13.37.80", :vlan => nil }
    def initialize(owner, *opts, &blk)
      @owner = owner
      @opts = merge_opts(DEFAULTS, opts.first)
      choose_sides

      # Three-way handshake if necessary
      if @opts[:transport] == :tcp
        frame(:client, nil, :syn)
        frame(:server, nil, :syn_ack)
        frame(:client, nil, :ack)
      end

      # Run the client's methods and close the connection if a block is provided
      if blk
        self.instance_eval(&blk)
        close
      end
    end

    def merge_opts(baseline, delta)
      res = baseline.dup

      # Validate the provided options
      (delta || {}).each do |k,v|
        raise ArgumentError, "Invalid option - #{k}" unless res.include?(k)
        res[k] = v
      end
      
      res[:src_port] ||= ((@owner.random[:src_port].pseudo_rand() & 0x3FFF) +
                          1025)

      # Accept IP addresses as IPAddr objects, strings, or integers.
      if res[:src_ip].class <= Integer
        res[:src_ip] = IPAddr.new(res[:src_ip].to_i, (res[:ipv6] ? 10 : 2))
      elsif res[:src_ip].class <= String
        res[:src_ip] = IPAddr.new(res[:src_ip])
      elsif res[:src_ip].class != IPAddr
        raise "Invalid format for src IP address: #{res[:src_ip].class}"
      end
      if res[:dst_ip].class <= Integer
        res[:dst_ip] = IPAddr.new(res[:dst_ip].to_i, (res[:ipv6] ? 10 : 2))
      elsif res[:dst_ip].class <= String
        res[:dst_ip] = IPAddr.new(res[:dst_ip])
      elsif res[:dst_ip].class != IPAddr
        raise "Invalid format for dst IP address: #{res[:dst_ip].class}"
      end
      res[:ipv6] = true if res[:src_ip].family == 10 or
                           res[:dst_ip].family == 10

      # Put the IP addresses (either v4 or v6) in host byte order
      if res[:ipv6]
        res[:src_ip] = iton128(res[:src_ip].to_i)
        res[:dst_ip] = iton128(res[:dst_ip].to_i)
      else
        res[:src_ip] = itonl(res[:src_ip].to_i)
        res[:dst_ip] = itonl(res[:dst_ip].to_i)
      end
      res
    end

    def choose_sides
      @port = [ @opts[:dst_port], @opts[:src_port] ]
      @mac = [ @opts[:dst_mac], @opts[:src_mac] ]
      @seq = [ @opts[:dst_seq], @opts[:src_seq] ]
      @ip = [ @opts[:dst_ip], @opts[:src_ip] ]
      @body = @opts[:body]
    end

    def close
      if @opts[:transport] == :tcp
        frame(:client, nil, :fin)
        frame(:server, nil, :fin)
        frame(:client, nil, :ack)
      end
    end

    def reset
      if @opts[:transport] == :tcp
        frame(:client, nil, :rst)
      end
    end

    def client(data)
      frame(:client, data)
    end

    def server(data)
      frame(:server, data)
    end

    def insert_delay(sec)
      @owner.timestamp += sec.to_f
    end

    def frame(direction, data, *flags)
      data ||= ''
      ipsum_offset = nil

      # Segment the data as needed
      hdr_length = 14 + 20 + (@opts[:transport] == :tcp ? 20 : 8)
      hdr_length += 20 if @opts[:ipv6]   # IPv6 header is 40 bytes, not 20
      if data.length + hdr_length > @opts[:mtu]
        split_len = @opts[:mtu] - hdr_length
        pieces = (data.length + split_len - 1) / split_len
        ret = ''
        pieces.times do |i|
          ret << frame(direction, data[split_len * i, split_len], *flags)
        end
        return ret
      end

      # Set our direction property
      if direction == :server || direction == :dst || !direction ||
         direction == 0
        src, dst = 0, 1
      else
        src, dst = 1, 0
      end

      # Ethernet header
      ret = @mac[dst] + @mac[src]    # src MAC, dst MAC
      if @opts[:ipv6]
        ret << "\x86\xdd"
      else
        ret << "\x08\x00"
      end

      # VLAN header(s)
      if @opts[:vlan]
        tag = "\x81\x00"
        [ @opts[:vlan] ].flatten.each do |vlan|
          ret = ret[0...-2] + tag + itons(vlan) + ret[-2,2]
          tag = "\x91\x00"
        end
      end

      # IPv6 Header
      ip_header_start = ret.length
      ip_header_length = 20
      if @opts[:ipv6]
        ip_header_length = 40
        payload_len = data.length + (@opts[:transport] == :tcp ? 20 : 8)
        ret << "\x60\x00\x00\x00"            # IP version, Class, Flow Label
        ret << "#{itons(payload_len)}"       # Payload length
        ret << (@opts[:transport] == :tcp ? "\x06" : "\x11")  # Protocol
        ret << "\x40"                        # Hop limit (TTL)
        ipsum_offset = ret.length
        ret << "#{@ip[src]}#{@ip[dst]}"      # IP addresses
        
      # IPv4 header
      else
        @random_fragment_id ||= PseudoConn::PseudoRand.new(2)
        frag_id = @owner.random[:ip_id].pseudo_rand() & 0xFFFF
        payload_len = data.length + (@opts[:transport] == :tcp ? 20 : 8) + 20
        ret << "\x45\x00#{itons(payload_len)}"     # IP version, ToS, length
        ret << "#{itons(frag_id)}\x00\x00\x40"     # ID, fragmentation, TTL
        ret << (@opts[:transport] == :tcp ? "\x06" : "\x11")  # Protocol
        ipsum_offset = ret.length
        ret << "\0\0"                              # Checksum placeholder
        ret << "#{@ip[src]}#{@ip[dst]}"            # IP addresses
      end
    
      # TCP header
      if @opts[:transport] == :tcp
        ret << "#{itons(@port[src])}#{itons(@port[dst])}"   # ports
        ret << itonl(@seq[src])                 # Sequence number
        ack = @seq[dst]
        ack = 0 if flags.include?(:syn)
        ret << itonl(ack)                       # ACK
        tf = 0x10    # ACK
        tf = 0x02 if flags.include?(:syn)
        tf += 0x02 if flags.include?(:syn_ack)
        tf += 0x01 if flags.include?(:fin)
        tf += 0x04 if flags.include?(:rst)
        ret << "\x50#{tf.chr}\x80\x00"          # hdr_len, flags, window
        tcpsum_offset = ret.length
        ret << "\x00\x00\x00\x00"               # checksum, URG pointer
        ret << data

        # Update the sequence number as needed
        seq_inc = data.length
        seq_inc += 1 if flags.include?(:syn) or flags.include?(:syn_ack) or
                        flags.include?(:fin)
        @seq[src] = (@seq[src] + seq_inc) % (2**32)

        # TCP Checksum
        checksum = 26 + data.length
        pos = ipsum_offset + 2
        while pos < ret.length do
          checksum += (ret[pos].ord << 8) + (ret[pos+1] || 0).ord
          if checksum > 0xFFFF
            checksum += 1
            checksum &= 0xFFFF
          end
          pos += 2
        end
        checksum = checksum ^ 0xFFFF
        ret[tcpsum_offset] = (checksum >> 8).chr
        ret[tcpsum_offset + 1] = (checksum & 0xFF).chr

      # UDP header
      else
        ret << "#{itons(@port[src])}#{itons(@port[dst])}"   # ports
        ret << ((data.length + 8) >> 8).chr                 # payload length
        ret << ((data.length + 8) & 0xFF).chr
        ret << "\x00\x00"                    # zero out the checksum
        ret << data
        ret.encode('binary')
      end

      # Go back now and compute the IP checksum (unless we're using IPv6,
      # which doesn't have a checksum)
      unless @opts[:ipv6]
        pos, checksum = ip_header_start, 0
        while pos < ip_header_start + ip_header_length
          checksum += (ret[pos].ord << 8) + ret[pos + 1].ord;
          if checksum > 0xFFFF
            checksum += 1
            checksum &= 0xFFFF
          end
          pos += 2
        end
        checksum = checksum ^ 0xFFFF
        ret[ipsum_offset] = (checksum >> 8).chr
        ret[ipsum_offset + 1] = (checksum & 0xFF).chr
      end

      # Frame header
      @owner.timestamp += (@owner.delay.to_f)
      hdr = itohl(@owner.timestamp.to_i)
      hdr << itohl(@owner.timestamp.tv_usec)
      hdr << itohl(ret.length)
      hdr << itohl(ret.length)

      # Return everything
      @owner.body << hdr
      @owner.body << ret
    end

    protected

    # Send this content on directly, or "explain" it.  ADD CODE HERE
    def proto_client(data)
      client(data)
    end
    def proto_server(data)
      server(data)
    end
    def proto_insert_delay(sec)
      insert_delay(sec)
    end  

    def itohs(num)
      (num & 0xFF).chr + ((num >> 8) & 0xFF).chr
    end

    def itohl(num)
      (num & 0xFF).chr + ((num >> 8) & 0xFF).chr +
      ((num >> 16) & 0xFF).chr + ((num >> 24) & 0xFF).chr
    end

    def itons(num)
      ((num >> 8) & 0xFF).chr + (num & 0xFF).chr
    end

    def itonl(num)
      ((num >> 24) & 0xFF).chr + ((num >> 16) & 0xFF).chr +
      ((num >> 8) & 0xFF).chr + (num & 0xFF).chr
    end

    def iton128(num)
      ret = ''
      16.times { ret = (num & 0xFF).chr + ret ; num >>= 8 }
      ret
    end

  end  # of class Connection

  # Deterministic pseudorandom number generator.  Not secure
  class PseudoRand
    LCG_A = 6364136223846793005
    LCG_C = 1442695040888963407

    def initialize(seed = 2147483587)
      @seed = seed
    end

    def pseudo_rand()
      @seed = (@seed * LCG_A + LCG_C) % 2**64
    end

  end  # of class PseudoRand
      
  def initialize(timestamp, delay)
    @timestamp = timestamp || Time.at(1234567890)
    @delay = delay || 0.01
    @body = String.new
    @random = {}
    @random[:src_port] = PseudoRand.new(1)
    @random[:ip_id] = PseudoRand.new(2)
  end

  def PseudoConn.pcap(timestamp = nil, delay = nil, &blk)
    pc = PseudoConn.new(timestamp, delay)
    raise ArgumentError, 'PseudoConn::pcap() block not supplied' unless blk
    pc.instance_eval &blk
    pc.to_pcap
  end

  def PseudoConn.test_case(timestamp = nil, delay = nil, &blk)
    pc = PseudoConn.new(timestamp, delay)
    raise ArgumentError, 'PseudoConn::pcap() block not supplied' unless blk
    pc.instance_eval &blk
    print(pc.to_pcap)
    true
  end    

  def insert_delay(sec)
    @timestamp += sec.to_f
  end

  def connection(*opts, &blk)
    Connection.new(self, *opts, &blk)
  end

  def to_pcap
    pcap_hdr = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00" +
               "\x00\x00\x00\x00\x00\x00\x00\x00" +
               "\xff\xff\x00\x00\x01\x00\x00\x00"
    return pcap_hdr + @body
  end

  attr_accessor :body, :timestamp, :delay, :random

end  # of class PseudoConn


# Some testing script
if __FILE__ == $0
  pcap = PseudoConn.pcap do

    # Connection one inside a block
    connection(:dst_ip => '1.2.3.4') do
      client "Hello"
      server "Yes?"
      client "Never mind"
    end

    # Connection two the manual way
    conn = connection(:ack => true, :dst_port => 1234)
    conn.client "Actually, are you still there?"
    conn.server "Yes?  What??"
    conn.client "If your'e going to be impatient, forget it."
    conn.close
  end
  File.open('sample.pcap', 'w') { |f| f.print pcap }
end
