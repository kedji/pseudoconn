#!/usr/bin/env ruby

# This class provides a simple scripting interface to simulating client/server
# network traffic over TCP or UDP.

class PseudoConn

  # This class holds everything necessary to manage a single TCP or UDP
  # connection.
  class Connection

    DEFAULTS = { :transport => :tcp, :ack => false, :mtu => 1500,
                 :src_port => nil, :src_seq => nil,
                 :dst_port => nil, :dst_seq => nil,
                 :src_mac => nil, :dst_mac => nil,
                 :src_ip => "10.0.0.1", :dst_ip => "42.13.37.80" }

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

      # Solidify the option hash in our fledgling object, initializing
      # particular empty values as necessary
      res[:src_port] ||= rand(30000) + 1025
      res[:dst_port] ||= rand(30000) + 1025
      res[:src_seq] ||= rand(2**32)
      res[:dst_seq] ||= rand(2**32)
      res[:src_mac] ||= (0..5).to_a.collect { rand(256).chr }.join
      res[:dst_mac] ||= (0..5).to_a.collect { rand(256).chr }.join

      # Accept IP addresses in dotted-quad notation
      if res[:src_ip].split('.').length == 4
        res[:src_ip] = res[:src_ip].split('.').collect { |x| x.to_i.chr }.join
      end
      if res[:dst_ip].split('.').length == 4
        res[:dst_ip] = res[:dst_ip].split('.').collect { |x| x.to_i.chr }.join
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

    def sleep(ms)
      @owner.timestamp += (ms.to_f / 1000)
    end

    def frame(direction, data, *flags)
      data ||= ''

      # Recursively segment the data as needed
      hdr_length = 14 + 20 + (@opts[:transport] == :tcp ? 20 : 8)
      if data.length + hdr_length > @opts[:mtu]
        split_len = @opts[:mtu] - hdr_length
        return frame(direction, data[0, split_len], *flags) +
               frame(direction, data[split_len..-1], *flags)
      end

      # Set our direction property
      if direction == :server || direction == :dst || !direction ||
         direction == 0
        src, dst = 0, 1
      else
        src, dst = 1, 0
      end

      # Ethernet header
      ret = @mac[src] + @mac[dst] + "\x08\x00"   # src MAC, dst MAC, protocol

      # IP header
      payload_len = data.length + (@opts[:transport] == :tcp ? 20 : 8) + 20
      ret << "\x45\x00#{itons(payload_len)}"     # IP version, ToS, length
      ret << "#{itons(rand(65536))}\x00\x00\x40" # ID, fragmentation, TTL
      ret << (@opts[:transport] == :tcp ? "\x06" : "\x11")  # Protocol
      ipsum_offset = ret.length
      ret << "\0\0"                              # Checksum placeholder
      ret << "#{@ip[src]}#{@ip[dst]}"            # IP addresses
    
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
        ret << "\x00\x00\x00\x00"               # checksum
        ret << data

        # Update the sequence number as needed
        seq_inc = data.length
        seq_inc += 1 if flags.include?(:syn) or flags.include?(:syn_ack) or
                        flags.include?(:fin)
        @seq[src] = (@seq[src] + seq_inc) % (2**32)

        # TCP Checksum
        checksum = 6
        pos = ipsum_offset
        while pos < ret.length do
          checksum += (ret[pos] << 8) + (ret[pos] || 0)
          if checksum > 0xFFFF
            checksum += 1
            checksum &= 0xFFFF
          end
          pos += 2
        end
        checksum = checksum ^ 0xFFFF
        ret[tcpsum_offset] = (checksum >> 8)
        ret[tcpsum_offset + 1] = (checksum & 0xFF)

      # UDP header
      else
        ret << "#{itons(@port[src])}#{itons(@port[dst])}"   # ports
        ret << ((data.length + 8) >> 8).chr                       # payload length
        ret << ((data.length + 8) & 0xFF).chr
        ret << "\x00\x00"                    # zero out the checksum
        ret << data
      end

      # Go back now and compute the IP checksum
      pos, checksum = 14, 0
      while pos < 34
        checksum += (ret[pos] << 8) + ret[pos + 1];
        if checksum > 0xFFFF
          checksum += 1
          checksum &= 0xFFFF
        end
        pos += 2
      end
      checksum = checksum ^ 0xFFFF
      ret[ipsum_offset] = (checksum >> 8)
      ret[ipsum_offset + 1] = (checksum & 0xFF)

      # Frame header
      @owner.timestamp += (@owner.delay.to_f)
      hdr = itohl(@owner.timestamp.to_i)
      hdr << itohl((@owner.timestamp.to_f.remainder(1) * 1000000).to_i)
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
    def proto_sleep(ms)
      sleep(ms)
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

  end  # of class Connection

  def initialize(timestamp, delay)
    @timestamp = timestamp || Time.now
    @delay = delay || 0.01
    @body = String.new
  end

  def PseudoConn.pcap(timestamp = nil, delay = nil, &blk)
    pc = PseudoConn.new(timestamp, delay)
    raise ArgumentError, 'PseudoConn::pcap() block not supplied' unless blk
    pc.instance_eval &blk
    pc.to_pcap
  end

  def sleep(ms)
    @timestamp += (ms.to_f / 1000)
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

  attr_accessor :body, :timestamp, :delay

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
