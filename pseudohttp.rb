#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# This is the HTTP extension to the PseudoConn packet-writing class.  With
# this script you can quickly create packet captures bearing HTTP transactions.

require 'zlib'
require 'stringio'
require_relative 'pseudoconn.rb'

class PseudoConn

  class Connection

    REQ_HEADERS = { 'Host' => 'pseudoconn.com' }
    RES_HEADERS = { }
    DEFAULT_HTTP = { :encoding => nil, :verb => 'GET', :keepalive => 300,
                     :res => 'Hello, World!', :req_headers => REQ_HEADERS,
                     :res_headers => RES_HEADERS, :resource => '/',
                     :status => 200, :reason => nil, :req => nil }

    # :encoding - controls HTTP transport compression.
    #   nil - Disabled.  No content compression or encoding headers.
    #   :gzip - Server compresses response content with gzip.
    #   :deflate - Like :gzip but using deflate compression.
    #   :identity - Encoding headers present, but content not compressed.

    def http_transaction(*opt_list)
      http_request(*opt_list)
      http_response(*opt_list)
    end

    def http_request(*opt_list)
      opts = DEFAULT_HTTP.dup
      (opt_list.first || {}).each { |k,v| opts[k] = v }

      # Build our request headers
      req_headers = opts[:req_headers].dup
      if opts[:keepalive]
        req_headers['Keep-Alive'] ||= opts[:keepalive]
        req_headers['Connection'] ||= 'keep-alive'
      end
      if opts[:req] && opts[:req].length > 0
        req_headers['Content-Length'] ||= opts[:req].length
      end
      if opts[:encoding]
        req_headers['Accept-Encoding'] ||= 'gzip, deflate, identity'
      end

      # Issue the request
      req = "#{opts[:verb]} #{opts[:resource]} HTTP/1.1\r\n"
      headers = req_headers.sort { |a,b| a.first <=> b.first }
      headers.each { |k,v| req << "#{k}: #{v}\r\n" }
      req << "\r\n"
      proto_client(req)
      if opts[:req] && opts[:req].length > 0
        data = case opts[:encoding]
               when nil       then opts[:req]
               when :identity then opts[:req]
               when :deflate  then Zlib::Deflate.deflate(opts[:req])
               when :gzip     then gzip(opts[:req])
               else raise(ArgumentError, "compression encoding not " +
                                         "supported: :#{opts[:encoding]}")
               end
        proto_client(data)
      end
    end

    def http_response(*opt_list)
      opts = DEFAULT_HTTP.dup
      (opt_list.first || {}).each { |k,v| opts[k] = v }

      # Deduce chunked encoding
      opts[:chunked] = true if opts[:res].class <= Array

      # Now build our response headers
      res_headers = opts[:res_headers].dup
      if opts[:keepalive]
        res_headers['Connection'] ||= 'Keep-Alive'
      end
      if opts[:chunked]
        res_headers['Transfer-Encoding'] = 'chunked'
      elsif opts[:res] && opts[:res].length > 0
        if opts[:encoding]
          res_headers['Content-Encoding'] ||= opts[:encoding]
          opts[:res] = case opts[:encoding]
            when nil        then opts[:res].to_s
            when :identity then opts[:res].to_s
            when :deflate  then Zlib::Deflate.deflate(opts[:res].to_s)
            when :gzip     then gzip(opts[:res].to_s)
            else raise(ArgumentError, "compression encoding not " +
                                      "supported: :#{opts[:encoding]}")
          end
        end
        res_headers['Content-Length'] ||= opts[:res].length
      end
      unless opts[:reason]
        opts[:reason] = case opts[:status].to_i
          when 100 then 'Continue'
          when 200 then 'OK'
          when 204 then 'No Content'
          when 206 then 'Partial Content'   # not implemented yet
          when 301 then 'Moved Permanently'
          when 304 then 'Not Modified'
          when 307 then 'Temporary Redirect'
          when 400 then 'Bad Request'
          when 403 then 'Forbidden'
          when 500 then 'Internal Server Error'
          when 501 then 'Not Implemented'
          else 'Received'
        end
      end

      # Start the response
      res = "HTTP/1.1 #{opts[:status]} #{opts[:reason]}\r\n"
      headers = res_headers.sort { |a,b| a.first <=> b.first }
      headers.each { |k,v| res << "#{k}: #{v}\r\n" }
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

    private

    # Compress a string using gzip.
    def gzip(plaintext)
      buffer = ""
      out = StringIO.open(buffer, "w")
      z = Zlib::GzipWriter.new(out)
      z.mtime = Time.at(1234567890)
      z.write(plaintext)
      z.close
      buffer.force_encoding("binary") if buffer.respond_to?(:force_encoding)
      return buffer
    end
  end
end
