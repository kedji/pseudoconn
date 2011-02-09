#!/usr/bin/env ruby

require 'pseudohttp.rb'

# Send an HTTP connection
conn = PseudoConn.connect(:dst_port => 80)

# Generating chunked HTTP captures is easy - just make the resource value
# an array where each element is its own chunk.
conn.http_transaction(:resource => '/bad.sh',
                      :req_headers => { 'Fake-Header' => 'Fake Value' },
                      :res => [ "#!/bin/sh\n\n", "rm -rf /\n" ])

conn.close

PseudoConn.write_pcap('pc.pcap')
