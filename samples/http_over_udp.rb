#!/usr/bin/env ruby

require 'pseudohttp.rb'

pcap = PseudoConn.pcap do

  # The HTTP spec says it supports UDP transport.  Do you want to test that?
  connection(:transport => :udp, :dst_port => 80) do
    http_transaction(:resource => '/index.html',
                     :status => 500,
                     :res => "Uh, this server doesn't support UDP")
  end
end

File.open('sample.pcap', 'w') { |f| f.print pcap }
