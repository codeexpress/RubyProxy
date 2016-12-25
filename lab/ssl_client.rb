require 'openssl'
require 'socket'
require 'net/https'

context = OpenSSL::SSL::SSLContext.new
context.ca_file = 'ca_cert.pem'
context.verify_mode = OpenSSL::SSL::VERIFY_NONE

tcp_client = TCPSocket.new '127.0.0.1', 9080
#tcp_client = TCPSocket.new '172.17.87.169', 443


ssl_client = OpenSSL::SSL::SSLSocket.new tcp_client, context
ssl_client.connect
ssl_client.puts "GET / HTTP/1.1\r\nHost: 172.17.87.169\r\n\r\n"


while line = ssl_client.gets
  puts ssl_client.gets
end
