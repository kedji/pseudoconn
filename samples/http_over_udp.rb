#!/usr/bin/env ruby
# encoding: ASCII-8bit
require_relative '../pseudohttp.rb'

pcap = PseudoConn.pcap do

  # The HTTP spec says it supports UDP transport.  Do you want to test that?
  connection(:transport => :udp, :dst_port => 80) do
    http_transaction(:resource => '/index.html',
                     :status => 500,
                     :res => "Uh, this server doesn't support UDP")
  end
end

fname = "#{File.basename(__FILE__)}.pcap"
File.open(fname, 'w') { |f| f.print pcap }
