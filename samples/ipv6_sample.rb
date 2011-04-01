#!/usr/bin/env ruby

require 'pseudoconn.rb'

pcap = PseudoConn.pcap do

  # Generate some simple traffic using an IPv6 connection
  connection(:src_ip => 'abcd:ef::0201', :dst_ip => 'abcd:ef::0403') do
    client "Hey there"
    server "What's up?"
  end
end

File.open('sample.pcap', 'w') { |f| f.print pcap }
