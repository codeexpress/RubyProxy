#! /usr/bin/env ruby

=begin 
5. Intercepting proxy which searches for specific text/pattern in the request/response
   and replaces it with a given text/pattern

Note that the requests and responses might not be ASCII characters which can be printed
on terminal. This will result in non-printable characters(gibberish) getting displayed
which might do wierd things to your terminal windows.

Examples of non readable requests are HTTPS traffic and other binary protocols
Examples of non readable responses are images/audio/video/binary data

Use following steps to deploy :
- Set your browser to use local socks5 proxy on port 1080 (localhost:1080)
- Run this ruby program (./5_intercept_and_replace_proxy.rb OR ruby 5_intercept_and_replace.rb)
- Start browsing. You should be able to see actual request/responses printed to terminal
- Requests get printed in plain text, responses are displayed as hex dump
- In all requests, the header value gzip, deflate is replaced by "" (this makes webserver to not compress the responses)
- In all responses, word 'the', if found, is made bold red and word 'and' is changed to bold and italic '&' in blue.
- These changes will be visible in browser
=end

# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'
require '../lib/socks_proxy.rb'

proxy = Proxy::SocksProxy.new #system_proxy: "192.168.0.10:80"

# logic procedure defines what can you do with intercepted messages
logic = Proc.new do |message|
  
  delimiter = message[:ssl]? '#' : ':'

  if message[:from] == :client 
    message[:data].gsub!(/gzip, deflate/,"")
    #puts message[:data]
    HexDump.print(message[:data], {hex_color: 31, delimiter: delimiter})
  end


  if message[:from] == :server    
    # for best results replace the same number of bytes. If not (like in this case)
    # firefox might not load complete pages
    #message[:data].gsub!(/ and /,"<font color=blue><b><i> & </i></b></font>")
    #message[:data].gsub!(/ the /,"<font color=red><b><i> the </i></b></font>")
    puts message[:data]
    #HexDump.print(message[:data], {hex_color: 32, line_size: 24})
  end
end

proxy.start(logic)
