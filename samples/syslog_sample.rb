#!/usr/bin/env ruby
# encoding: ASCII-8bit
require_relative '../pseudoconn.rb'

# This sample demonstrates the old-skool way to manage connections.  It's
# necessary if you need to weave connection data together or inject RST frames.

pcap = PseudoConn.pcap do

  # Send a partial HTTP connection that gets reset prematurely
  tcp1 = connection(:src_ip => '1.2.3.4', :dst_ip => '21.31.41.51')
  tcp1.client "GET /file1 HTTP/1.0\r\nHost: Server1\r\n\r\n"
  tcp1.server "HTTP/1.0 200 Okie Dokie\r\nContent-Le"
  tcp1.reset

  # Put a fake syslog message in the capture
  syslog = connection(:dst_port => 514,
                      :src_ip => '10.0.0.5',
                      :dst_ip => '10.0.0.34',
                      :transport => :udp)
  syslog.client("<128>HTTP connection was reset")

  # Start another connection, also reset prematurely.  How about RFB this time.
  tcp2 = connection(:src_ip => '4.3.2.1', :dst_ip => '21.31.41.51')
  tcp2.server "RFB 003.008\n"
  tcp2.client "RFB 003.008\x00"
  tcp2.server "\x02\x02\x10"
  tcp2.client "\x02" 
  tcp2.server "\x0e32\xda\x9f\xf1]\xe0\xc7$\xac\x1a\xd3\xab;\xc3"
  tcp2.reset

  # And one more syslog message
  syslog.client("<32>RFB connection was reset")
end

fname = "#{File.basename(__FILE__)}.pcap"
File.open(fname, 'w') { |f| f.print pcap }
