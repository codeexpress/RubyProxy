#! /usr/bin/env ruby

=begin 
2. Basic Proxy which uses another upstream HTTP proxy and listens on a non-default SOCKS port.
This is a example of proxy which listens on port 9000 and relays requests to an upstream HTTP proxy.

You'll need to specify the upstream proxy when you are on a corporate/home network which uses
 a proxy to connect to internet or the designated destination server.

Use following steps to deploy :
- Set your browser to use local socks5 proxy on port 9000 (localhost:9000)
- Run this ruby program (./2_basic_proxy.rb OR ruby 2_basic_proxy.rb)
- Start browsing. You should be able to see a hex dump of request and responses.
=end

# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'
require '../lib/socks_proxy.rb'

proxy = Proxy::SocksProxy.new port: 1080, system_proxy:"199.172.169.11:80", is_http_proxy: true

proxy.start
