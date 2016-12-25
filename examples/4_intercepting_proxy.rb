#! /usr/bin/env ruby

=begin 
4. Intercepting proxy which differentiates between the requests/responses 
and deals with them differently.

Note that the requests and responses might not be ASCII characters which can be printed
on terminal. This will result in non-printable characters(gibberish) getting displayed
which might do wierd things to your terminal windows.

Examples of non readable requests are HTTPS traffic and other binary protocols
Examples of non readable responses are images/audio/video/binary data

Use following steps to deploy :
- Set your browser to use local socks5 proxy on port 1080 (localhost:1080)
- Run this ruby program (./4_intercepting_proxy.rb OR ruby 4_intercepting_proxy.rb)
- Start browsing. You should be able to see actual request/responses printed to terminal
- Requests get printed in plain text, responses are displayed as hex dump
=end

# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'
require '../lib/socks_proxy.rb'

proxy = Proxy::SocksProxy.new system_proxy: "192.168.0.10:80"

# logic procedure defines what can you do with intercepted messages
# In this case, it simply prints them
logic = Proc.new do |message|
  
  # variable src is set to :from_client for requests and :from_server for responses
  if message[:from] == :client 
    puts "This is a Client -> Server request (#{message[:from_ip]} -> #{message[:to_ip]}) :"
    puts message[:data]
  end
  
  if message[:from] == :server 
    puts "This is a Server -> Client response (#{message[:to_ip]} -> #{message[:from_ip]}). Hex dump is: "
    HexDump.print(message[:data])
  end

end
  
proxy.start(logic)
