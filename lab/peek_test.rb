require 'openssl'
require 'socket'
require 'net/https'

client = TCPSocket.new '172.17.87.169', 443

client.puts "GET / HTTP/1.1\r\nHost: 172.17.87.169\r\n\r\n"

while line = client.recvmsg(1000, Socket::MSG_PEEK)[0]
  puts line
  break if line.length ==0 
end

puts "Socket closed"

