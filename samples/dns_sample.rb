#!/usr/bin/env ruby

$LOAD_PATH << File.split(__FILE__).first
require 'pseudodns.rb'

pcap = PseudoConn.pcap do

  # Send a query by itself without a connection object.
  dns_query('www.yahoo.com')

  # Send the same query, specifying some connection information
  dns_query('www.yahoo.com', :src_ip => '1.2.3.4', :dst_ip => '8.8.8.8')

  # Send a simple DNS answer by itself inside a connection object
  connection(:transport => :udp, :dst_port => 53) do
    dns_answer('www.fake.com', '1.2.3.4')
  end

  # Send three answers to the provided PTR lookup
  dns_answer('2.3.4.5.IN-ADDR.ARPA',
    [ 'second.fake.com', 'third.fake.com', 'fourth.fake.com' ],
    PseudoConn::PSEUDO_DNS_PTR)

  # Send two answers of different types to the provided PTR lookup
  dns_answer('91.82.73.84.IN-ADDR.ARPA',
    [
      [ 'this is information for a TXT record', PseudoConn::PSEUDO_DNS_TXT ],
      [ 'this TXT record has a short TTL', PseudoConn::PSEUDO_DNS_TXT, 2 ]
    ], PseudoConn::PSEUDO_DNS_PTR)

  # Perform a query and get an answer in one call.
  dns_lookup('www.sample.com', '6.7.8.9')

  # Peform a query, get back an NX domain
  dns_lookup('www.this.host.aint.real.org', nil)

  # Perform a query, get back an AAAA record
  dns_lookup('www.sample6.com', 'abcd:1234::0001', PseudoConn::PSEUDO_DNS_AAAA)

  # Peform a query, get back responses, the first and third of which contain
  # an rname which differs from the qname
  dns_lookup('multihost.com',
    [
      [ '10.0.0.13', PseudoConn::PSEUDO_DNS_A, 3600, 'www.multihost.com' ],
      [ '10.0.0.14', PseudoConn::PSEUDO_DNS_A, 3600 ],
      [ '10.0.0.15', PseudoConn::PSEUDO_DNS_A, 3600, 'ftp.multihost.com' ]
    ])

end

File.open('sample.pcap', 'w') { |f| f.print pcap }
