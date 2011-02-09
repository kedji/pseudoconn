#!/usr/bin/env ruby

# This is the HTTP extension to the PseudoConn packet-writing class.  With
# this script you can quickly create packet captures bearing HTTP transactions.

$LOAD_PATH << File.split(__FILE__).first
require 'pseudoconn.rb'

class PseudoConn

  REQ_HEADERS = { 'Host' => 'pseudoconn.com' }
  RES_HEADERS = { }
  DEFAULT_HTTP = { :verb => 'GET', :keepalive => 300, :req => nil,
                   :res => 'Hello, World!', :req_headers => REQ_HEADERS,
                   :res_headers => RES_HEADERS, :resource => '/',
                   :status => 200, :reason => nil }

  def http_transaction(*opt_list)
    http_request(*opt_list)
    http_response(*opt_list)
  end

  def http_request(*opt_list)
    opts = DEFAULT_HTTP.dup
    opt_list.first.each { |k,v| opts[k] = v }

    # Build our request headers
    req_headers = opts[:req_headers]
    if opts[:keepalive]
      req_headers['Keep-Alive'] ||= opts[:keepalive]
      req_headers['Connection'] ||= 'keep-alive'
    end
    if opts[:req] && opts[:req].length > 0
      req_headers['Content-Length'] = opts[:req].length
    end

    # Issue the request
    req = "#{opts[:verb]} #{opts[:resource]} HTTP/1.1\r\n"
    req_headers.each { |k,v| req << "#{k}: #{v}\r\n" }
    req << "\r\n"
    proto_client(req)
    if opts[:req] && opts[:req].length > 0
      proto_client(opts[:req])
    end
  end

  def http_response(*opt_list)
    opts = DEFAULT_HTTP.dup
    opt_list.first.each { |k,v| opts[k] = v }

    # Deduce chunked encoding
    opts[:chunked] = true if opts[:res].class <= Array

    # Now build our response headers
    res_headers = opts[:res_headers]
    if opts[:keepalive]
      res_headers['Connection'] ||= 'Keep-Alive'
    end
    if opts[:chunked]
      res_headers['Transfer-Encoding'] = 'chunked'
    elsif opts[:res] && opts[:res].length > 0
      res_headers['Content-Length'] = opts[:res].length
    end
    unless opts[:reason]
      opts[:reason] = case opts[:status].to_i
        when 100: 'Continue'
        when 200: 'OK'
        when 204: 'No Content'
        when 206: 'Partial Content'   # not implemented yet
        when 301: 'Moved Permanently'
        when 304: 'Not Modified'
        when 307: 'Temporary Redirect'
        when 400: 'Bad Request'
        when 403: 'Forbidden'
        when 500: 'Internal Server Error'
        when 501: 'Not Implemented'
        else ; 'Received'
      end
    end

    # Start the response
    res = "HTTP/1.1 #{opts[:status]} #{opts[:reason]}\r\n"
    res_headers.each { |k,v| res << "#{k}: #{v}\r\n" }
    res << "\r\n"
    proto_server(res)

    # Is this a chunked response?  If so, break the content into pieces
    if opts[:chunked]
      # Prepend a hex length to each chunk
      opts[:res].each do |chunk|
        res = "#{chunk.length.to_s(16)}\r\n"
        res << chunk
        res << "\r\n"
        proto_server(res)
      end
      proto_server("0\r\n\r\n")

    # Is this a regular response?
    else
      data = opts[:res].to_s
      proto_server(data) unless data.empty?
    end
  end

end
