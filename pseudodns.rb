#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# This is the DNS extension to the PseudoConn packet-writing class. With
# this script you can quickly create packet captures containing DNS queries
# and/or responses.

require 'ipaddr'
require_relative 'pseudoconn.rb'

class PseudoConn

  # Supported DNS record types.  You can specify any record type you wish,
  # but these are the ones given explicit support by PseudoConn.
  PSEUDO_DNS_A      = 0x01
  PSEUDO_DNS_NS     = 0x02
  PSEUDO_DNS_CNAME  = 0x05
  PSEUDO_DNS_SOA    = 0x06
  PSEUDO_DNS_PTR    = 0x0c
  PSEUDO_DNS_MX     = 0x0f
  PSEUDO_DNS_TXT    = 0x10
  PSEUDO_DNS_AAAA   = 0x1c
  PSEUDO_DNS_OPT    = 0x29

  # Additional option types
  OPT_CSUBNET       = 0x8

  class Connection

    def dns_lookup(qname, answers, qtype = PSEUDO_DNS_A, opts = {})
      @owner.random[:dns_id] ||= PseudoRand.new(0x4a1d)
      opts = opts.dup
      opts[:id] ||= (@owner.random[:dns_id].pseudo_rand() & 0xFFFF)
      dns_query(qname, qtype, opts)
      dns_answer(qname, answers, qtype, opts)
    end

    def dns_query(qname, qtype = PSEUDO_DNS_A, opts = {})
      @owner.random[:dns_id] ||= PseudoRand.new(0x4a1d)
      id = opts[:id]
      id ||= (@owner.random[:dns_id].pseudo_rand() & 0xFFFF)
      recurse = opts.fetch(:rd, true)
      flags = recurse ? 0x0100 : 0x0000
      addtl = opts.fetch(:additional, [])
      addtl = [ addtl ] if not addtl.is_a?(Array)
      if addtl.length >= 2 && addtl[1].is_a?(Integer)
        addtl = [ addtl ]
      end
      query = itons(id) + itons(flags) + itons(1) + itons(0) +
              itons(0) + itons(addtl.length)
      query << label_encode(qname)
      query << (itons(qtype) + itons(1))
      addtl.each_with_index do |ans, idx|
        ext = ''
        next if not ans[1] == PSEUDO_DNS_OPT
        ext << 0.chr             # name
        ext << itons(ans[1])     # type
        ext << itonl(0x10000000) # payload size
        ext << itons(0x8000)     # accept DNSSEC RRs
        dns_opt = parse_dns_opt(ans.first, ans[2])
        next if dns_opt == nil
        ext << itons(dns_opt.length)
        ext << dns_opt
        query << ext
      end
      proto_client(query)
    end

    def dns_answer(qname, answers, qtype = PSEUDO_DNS_A, opts = {})
      @owner.random[:dns_id] ||= PseudoRand.new(0x4a1d)
      addtl = opts.fetch(:additional, [])
      auth  = opts.fetch(:authority, [])
      id    = opts[:id]
      id ||= (@owner.random[:dns_id].pseudo_rand() & 0xFFFF)
      recurse = opts.fetch(:rd, true)
      flags   = recurse ? 0x8180 : 0x8080
      priority = 100

      if answers
        # Special case - if they just give one value, it's an answer
        answers = [ answers ] unless answers.class <= Array

        # If they give us an array with either 2 or 3 values, it may be an
        # array of independent answers, or it could be an array describing - in
        # detail - a single answer.  If the second element is a record type (an
        # integer), assume it's one detailed answer.  Otherwise assume it's
        # an array of answers.
        if answers.length >= 2 && answers[1].class <= Integer
          answers = [ answers ]
        end

      # If no answers are provided, this is an NX domain
      else
        flags += 3
        answers = []
      end

      # These may be arrays of separate answers or a single answer
      # Second element determines which
      addtl = [ addtl ] unless addtl.class <= Array
      if (addtl.length >= 2) and addtl[1].class <= Integer
        addtl = [ addtl ]
      end

      auth = [ auth ] unless auth.class <= Array
      if (auth.length >= 2) and auth[1].class <= Integer
        auth = [ auth ]
      end

      # Construct the header and the query field
      answer = itons(id) + itons(flags) + itons(1)
      answer << (itons(answers.length) + itons(auth.length) + itons(addtl.length))
      answer << label_encode(qname)
      answer << (itons(qtype) + itons(1))
      addtl.each { |e| answers << e }
      auth.each  { |e| answers << e }

      # Construct each answer
      answers.each_with_index do |ans, ii|
        tmp = ''
        ans = [ ans ] unless ans.class <= Array
        ip = nil
        if ans.first.to_s =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ or
           ans.first.to_s =~ /^[0-9A-Fa-f\:]{3,39}$/
          ip = (IPAddr.new(ans.first.to_s) rescue nil)
        end

        # If this is a valid IP address, assume this is an A or AAAA record. If
        # the query type is PTR, assume CNAME. Otherwise assume a TXT record.
        if ans.length < 2
          if ip.class <= IPAddr and ip.ipv4?
            ans << PSEUDO_DNS_A
          elsif ip.class <= IPAddr and ip.ipv6?
            ans << PSEUDO_DNS_AAAA
          elsif qtype == PSEUDO_DNS_NS
            ans << PSEUDO_DNS_NS
          elsif qtype == PSEUDO_DNS_PTR
            ans << PSEUDO_DNS_PTR
          else
            ans << PSEUDO_DNS_TXT
          end
        end
        ans << 86400 if ans.length < 3
        ans << qname if ans.length < 4

        # Construct the answer based on its record type.
        if (ans[1] == PSEUDO_DNS_OPT)
          tmp << 0.chr         
        elsif ans[3] == qname
          tmp << itons(0xc00c) # pointer to original qname
        else
          tmp << label_encode(ans[3] || ans.first)   # answer name
        end
        tmp << itons(ans[1])            # answer type
        if (ans[1] != PSEUDO_DNS_OPT)
          tmp << itons(1)               # IPv4 answer class
          tmp << itonl(ans[2])          # TTL
        else
          tmp << itonl(0xffff0000)      # max payload
          tmp << itons(0x8000)          # Accept DNSSEC security RRs
        end
        data = ans.first

        case ans[1]
          when PSEUDO_DNS_A then
            data = itonl(ip.to_i)
          when PSEUDO_DNS_NS then
            data = label_encode(data || "ns#{ii}.#{ans.first}")
          when PSEUDO_DNS_CNAME then
            data = label_encode(data)
          when PSEUDO_DNS_SOA then
            data = label_encode(data)
            data << label_encode("r.#{qname}")
            data << itonl(18)
            data << itonl(10800)
            data << itonl(3600)
            data << itonl(604800)
            data << itonl(3600)
          when PSEUDO_DNS_PTR then
            data = label_encode(data)
          when PSEUDO_DNS_TXT then
            data = label_encode(data)
            data[-1,1] = ''
          when PSEUDO_DNS_MX then
            data = itons(priority) + label_encode(data)
            data[-1,1] = ''
            priority += 100
          when PSEUDO_DNS_AAAA then
            data = iton128(ip.to_i)
          when PSEUDO_DNS_OPT then
            data = parse_dns_opt(data, ans[2])
            next if data == nil
        end
        tmp << itons(data.length)
        tmp << data
        answer << tmp
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

    def parse_dns_opt(opt, cidr)
      optdata = nil
      if opt == OPT_CSUBNET
        ip = IPAddr.new(cidr.split('/').first) rescue nil
        return nil unless ip
        mask = cidr.split('/')[1]
        return nil unless mask
        mask = mask.to_i
        if ip.ipv4?
          family = 1
          bmask  = (2**32-1) << (32 - mask)
          subnet = itonl(ip.to_i & bmask)
        else # IPv6
          family = 2
          bmask  = (2**128-1) << (128 - mask)
          subnet = iton128(ip.to_i & bmask)
        end
        data    = itons(family) + mask.chr + 0x00.chr + subnet
        optdata = itons(opt) + itons(data.length) + data
      end
      return optdata
    end

  end  # of class Connection

  def dns_lookup(qname, answers, *conn_opts)
    qtype = PSEUDO_DNS_A
    qtype = conn_opts.shift if conn_opts.first.class <= Integer
    opts = (conn_opts.first || {})
    opts[:transport] = :udp
    opts[:dst_port] ||= 53
    con_opts = {}
    opts.reject! { |k, v| Connection::DEFAULTS.keys.include?(k) ? (con_opts[k] = v; true) : false }
    connection(con_opts) { dns_lookup(qname, answers, qtype, opts) }
  end

  def dns_query(qname, *conn_opts)
    qtype = PSEUDO_DNS_A
    qtype = conn_opts.shift if conn_opts.first.class <= Integer
    opts = (conn_opts.first || {})
    opts[:transport] = :udp
    opts[:dst_port] ||= 53
    con_opts = {}
    opts.reject! { |k, v| Connection::DEFAULTS.keys.include?(k) ? (con_opts[k] = v; true) : false }
    connection(con_opts) { dns_query(qname, qtype, opts) }
  end

  def dns_answer(qname, answers, *conn_opts)
    qtype = PSEUDO_DNS_A
    qtype = conn_opts.shift if conn_opts.first.class <= Integer
    opts = (conn_opts.first || {})
    opts[:transport] = :udp
    opts[:dst_port] ||= 53
    con_opts = {}
    opts.reject! { |k, v| Connection::DEFAULTS.keys.include?(k) ? (con_opts[k] = v; true) : false }
    connection(con_opts) { dns_answer(qname, answers, qtype, opts) }
  end

end
