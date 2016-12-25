#! /usr/bin/env ruby

=begin 
1. Basic proxy
This is an example of socks proxy in its default configuration.
Use following steps to deploy :
- Set your browser to use local socks5 proxy on port 1080 (localhost:1080)
- Run this ruby program (./1_basic_proxy.rb OR ruby 1_basic_proxy.rb)
- Start browsing. You should be able to see a hex dump of request and responses.
=end

# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'
require '../lib/socks_proxy.rb'

proxy = Proxy::SocksProxy.new

proxy.start
