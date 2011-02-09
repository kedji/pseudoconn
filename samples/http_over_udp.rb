#!/usr/bin/env ruby

require 'pseudohttp.rb'

# The HTTP spec says it supports UDP transport.  Do you want to test that?
udp = PseudoConn.connect(:transport => :udp, :dst_port => 80)
udp.http_transaction(:resource => '/index.html',
                     :status => 500,
                     :res => "Uh, this server doesn't support UDP")

PseudoConn.write_pcap('sample.pcap')
