#!/usr/bin/env ruby

$LOAD_PATH << File.split(__FILE__).first
require 'pseudodns.rb'

# Send a DNS request by itself
PseudoConn.dns_query('www.yahoo.com')

# Send a simple DNS answer by itself
PseudoConn.dns_answer('www.fake.com', '1.2.3.4')

# Send three answers to the provided PTR lookup
PseudoConn.dns_answer('2.3.4.5.IN-ADDR.ARPA',
  [ 'second.fake.com',
    [ 'this is information for a TXT record', PseudoConn::PSEUDO_DNS_TXT ],
    [ 'this TXT record contains a short TTL', PseudoConn::PSEUDO_DNS_TXT, 2 ] ],
  PseudoConn::PSEUDO_DNS_PTR)

PseudoConn.write_pcap('pc.pcap')
