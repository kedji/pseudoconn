#!/usr/bin/env ruby

# This is the DNS extension to the PseudoConn packet-writing class.  With
# this script you can quickly create packet captures containing DNS queries
# and/or responses.  Currently only the IPv4 class is supported

require 'ipaddr'

$LOAD_PATH << File.split(__FILE__).first
require 'pseudoconn.rb'

class PseudoConn

  # Supported DNS record types.  You can specify any record type you wish,
  # but these are the ones given explicit support by PseudoConn.
  PSEUDO_DNS_A      = 0x01
  PSEUDO_DNS_CNAME  = 0x05
  PSEUDO_DNS_PTR    = 0x0c
  PSEUDO_DNS_MX     = 0x0f
  PSEUDO_DNS_TXT    = 0x10

  def PseudoConn.dns_query(qname, *conn_opts)
    qtype = PSEUDO_DNS_A
    qtype = conn_opts.shift if conn_opts.first.class <= Integer
    opts = (conn_opts.first || {})
    opts[:transport] = :udp
    opts[:dst_port] ||= 53
    conn = PseudoConn.connect(opts)
    conn.dns_query(qname, qtype)
  end

  def PseudoConn.dns_answer(qname, answers, *conn_opts)
    qtype = PSEUDO_DNS_A
    qtype = conn_opts.shift if conn_opts.first.class <= Integer
    opts = (conn_opts.first || {})
    opts[:transport] = :udp
    opts[:dst_port] ||= 53
    conn = PseudoConn.connect(opts)
    conn.dns_answer(qname, answers, qtype)
  end

  def dns_query(qname, qtype = PSEUDO_DNS_A, id = nil)
    id ||= rand(2**16)
    flags = 0x0100
    query = itons(id) + itons(flags) + itons(1) + itons(0) + itons(0) + itons(0)
    query << label_encode(qname)
    query << (itons(qtype) + itons(1))
    proto_client(query)
  end

  def dns_answer(qname, answers, qtype = PSEUDO_DNS_A, id = nil)
    id ||= rand(2**16)
    flags = 0x8180
    priority = 100

    # Special case - if they just give one value, it's an answer
    answers = [ answers ] unless answers.class <= Array

    # If they give us an array with either 2 or 3 values, it may be an
    # array of independent answers, or it could be an array describing - in
    # detail - a single answer.  If the second element is a record type (an
    # integer), assume it's one detailed answer.  Otherwise assume it's
    # an array of answers.
    if (answers.length == 2 or answers.length == 3) and
       answers[1].class <= Integer
      answers = [ answers ]
    end

    # Construct the header and the query field
    answer = itons(id) + itons(flags) + itons(1)
    answer << (itons(answers.length) + itons(0) + itons(0))
    answer << label_encode(qname)
    answer << (itons(qtype) + itons(1))

    # Construct each answer
    answers.each do |ans|
      ans = [ ans ] unless ans.class <= Array
      ip = nil
      if ans.first.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
        ip = (IPAddr.new(ans.first.to_s) rescue nil)
      end

      # If this is a valid IPv4 address, assume this is an A-type recrd.  If
      # the query type is PTR, assume CNAME.  Otherwise assume a TXT record.
      if ip
        ans << PSEUDO_DNS_A
      elsif qtype == PSEUDO_DNS_PTR
        ans << PSEUDO_DNS_CNAME
      else
        ans << PSEUDO_DNS_TXT
      end
      ans << 86400 if ans.length < 3

      # Construct the answer based on its record type.
      answer << itons(0xc00c)   # answer name (always same as qname for now)
      answer << itons(ans[1])   # answer type
      answer << itons(1)        # answer class (IPv4 for now)
      answer << itonl(ans[2])   # ttl
      data = ans[0]
      case ans[1]
        when PSEUDO_DNS_A:
          data = itonl(ip.to_i)
        when PSEUDO_DNS_CNAME:
          data = label_encode(data)
        when PSEUDO_DNS_TXT:
          data = label_encode(data)
          data[-1,1] = ''
        when PSEUDO_DNS_MX:
          data = itons(priority) + label_encode(data)
          data[-1,1] = ''
          priority += 100
      end
      answer << itons(data.length)
      answer << data
    end
    proto_server(answer)
  end
    
private

  def label_encode(str, pkt = '')
    labels = str.split('.')
    encoded = ''
    labels.each do |label|
      raise "label too long: '#{label}'" if label.length > 255
      encoded << label.length.chr
      encoded << label
    end
    encoded << "\0"
  end

end
