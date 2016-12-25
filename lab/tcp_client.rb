require 'openssl'
require 'socket'
require 'net/https'

tcp_client = TCPSocket.new '172.17.87.169', 443

tcp_client.puts "GET / HTTP/1.1\r\nHost: 172.17.87.169\r\n\r\n"


while line = tcp_client.gets
  puts line
end

