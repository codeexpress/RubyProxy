#!/usr/bin/ruby

require "socket"
require "openssl"
require "thread"

listeningPort = Integer(ARGV[0])

server = TCPServer.new(listeningPort)
sslContext = OpenSSL::SSL::SSLContext.new
sslContext.cert = OpenSSL::X509::Certificate.new(File.open("certs/server.crt"))
sslContext.key = OpenSSL::PKey::RSA.new(File.open("certs/server.key"))
sslServer = OpenSSL::SSL::SSLServer.new(server, sslContext)
sslServer.start_immediately = false # don't immediately start TLS

puts "Listening on port #{listeningPort}"

loop do
  connection = sslServer.accept
  Thread.new {
    connection.accept  # Upgrade from plain text to SSL
    puts connection.class.public_instance_methods
    begin
      while (lineIn = connection.recv(1))
        lineIn = lineIn.chomp
        $stdout.puts "=> " + lineIn
        lineOut = "You said: " + lineIn
        $stdout.puts "<= " + lineOut
        connection.puts lineOut
      end
    rescue
      $stderr.puts $!
    end
  }
end
