#!/usr/bin/env ruby
# encoding: ASCII-8bit
require_relative '../pseudoconn.rb'

pcap = PseudoConn.pcap do

  # Generate some simple traffic using an IPv6 connection
  connection(:src_ip => 'abcd:ef::0201', :dst_ip => 'abcd:ef::0403') do
    client "Hey there"
    server "What's up?"
  end
end

fname = "#{File.basename(__FILE__)}.pcap"
File.open(fname, 'w') { |f| f.print pcap }
