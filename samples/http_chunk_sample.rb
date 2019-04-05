#!/usr/bin/env ruby
# encoding: ASCII-8bit
require_relative '../pseudohttp.rb'

pcap = PseudoConn.pcap do

  # Generating chunked HTTP captures is easy - just make the resource value
  # an array where each element is its own chunk.
  connection(:dst_port => 80) do
    http_transaction(:resource => '/bad.sh',
                     :req_headers => { 'Fake-Header' => 'Fake Value' },
                     :res => [ "#!/bin/sh\n\n", "rm -rf /\n" ])
  end
end

fname = "#{File.basename(__FILE__)}.pcap"
File.open(fname, 'w') { |f| f.print pcap }
