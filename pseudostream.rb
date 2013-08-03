#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require_relative 'pseudoconn.rb'

# This interface is used to inject packets directly onto a NIC
class PseudoStream < PseudoConn

  class Injector

    def initialize(interface = nil, random = nil)
      require 'socket'
      @timestamp = Time.now
      @delay = 0
      @random = random
      @raw = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_RAW)
      if interface
        @raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_BINDTODEVICE, interface)
      end
    end
    attr_accessor :random, :timestamp, :delay

    def body
      self
    end

    # This method, which gets called by frame(), either gets a 16-byte pcap
    # header (which can be ignored), or a packet, starting with the 14-byte
    # ethernet header.  Inject the latter.
    def <<(data)
      return nil if data.length == 16
      return nil if data[12, 2] != "\x08\x00"  # only support IPv4 for now
      data[0, 14] = ''
      data.force_encoding('BINARY')
      dst_ip = data[16, 4].split('').collect { |x| x.ord.to_s }.join('.')
      dst_port = data[22].ord * 256 + data[23].ord
      addr = Socket.pack_sockaddr_in(dst_port, dst_ip)
      @raw.send(data, Socket::AF_INET, addr)
    end

  end  # of Injector class

  def PseudoStream.inject(interface = nil, &blk)
    pc = PseudoStream.new(nil, 0)
    pc.injector = Injector.new(interface, pc.random)
    pc.instance_eval(&blk)
  end

  # Override the connection method to use our injector object
  def connection(*opts, &blk)
    Connection.new(@injector, *opts, &blk)
  end
  attr_accessor :injector

end

