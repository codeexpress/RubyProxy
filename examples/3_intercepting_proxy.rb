#! /usr/bin/env ruby

=begin 
3. Intercepting proxy which intercepts the requests and responses and prints them.
This is an example of proxy which intercepts the requests and responses as raw bytes
and prints them on terminal.

Note that the requests and responses might not be ASCII characters which can be printed
on terminal. This will result some non-printable characters (gibberish) getting displayed.

Examples of non readable requests are HTTPS traffic and other binary protocols
Examples of non readable responses are images/audio/video/binary data

Use following steps to deploy :
- Set your browser to use local socks5 proxy on port 9000 (localhost:9000)
- Run this ruby program (./3_intercepting_proxy.rb OR ruby 3_intercepting_proxy.rb)
- Start browsing. You should be able to see a hex dump of request and responses.
=end

# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'
require '../lib/socks_proxy.rb'

proxy = Proxy::SocksProxy.new system_proxy: "192.168.0.10:80"

# logic procedure defines what can you do with intercepted messages
# message is a hash with these variables filled in by the proxy. CHECK > Insert docs for message format here <
# In this case, it simply prints them
logic = Proc.new do |message|
  puts "*************************************"
  puts message[:data]
  puts "*************************************"
end
  
proxy.start(logic)
