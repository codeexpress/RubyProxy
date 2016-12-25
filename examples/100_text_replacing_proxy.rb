# if you have installed the socks_proxy gem, then you can
# directly require the gem using:
# require 'socks_proxy'

require '../lib/socks_proxy.rb'


  proxy = Proxy::SocksProxy.new
  
  logic = Proc.new do |message, src, tid|
    puts src
    color = (tid % 7) + 31
    HexDump.print(message, { hex_color: color })

    if src == :from_client
      #puts "old message:\n #{message}"
      message.gsub!(/gzip, deflate/,"")
      #message.replace "hey hey hey whats this ip"
      #puts "new message:\n #{message}"
     # HexDump.print(message, {hex_color: 32})
    end


    if src == :from_server
      message.gsub!(/the/,"<font color=red><b> </b></font>")
      #message.replace "hey hey hey whats this ip"
      #puts "new message: #{message}"
    # HexDump.print(message, {hex_color: 32})
    end
  end
  
  main_thread = Thread.start { 
    proxy.start(logic)
  }
  
#  Thread.start {
#    loop do
#      puts proxy.stats
#      sleep 2
#    end
#  }
  
  main_thread.join

