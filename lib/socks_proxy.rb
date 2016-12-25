require 'socket'
require 'hex_dump'
require 'openssl'
require 'logger'
require 'resolv'
require 'net/http'
require 'uri'      
require 'json'


module Proxy 
  SOCKS_VER   = 5
  RSV         = 0
  ATYP_IPV4   = 1
  ATYP_DNS    = 3
  AUTH_METHOD_NOAUTH = 0
  LIB_DIR = File.expand_path(File.dirname(__FILE__)) # path of current (lib) directory

  # SocksRequest
  class SocksRequest
    attr_reader :ver, :cmd, :rsv, :atype, :dst_addr, :dst_port, :dst_addr_str

    def initialize(*argv)
      params = argv.flatten! # what comes in is an array inside array [[]]. flatten makes it []
      puts "params are >>>>>>>>>>>>>> #{params}"
      @ver, @cmd, @rsv, @atyp, @dst_addr, @dst_port = params
      @dst_addr_str = Proxy::ip_dec_to_dotted(@dst_addr)    
    end

  end # SocksRequest class ends

  class SocksResponse
    attr_accessor :ver, :rep, :rsv, :atyp, :bnd_addr, :bnd_port
    
    def initialize(bnd_port)
      @ver = [SOCKS_VER].pack('C')
      @rep = @rsv = [RSV].pack('C')
      @atyp = [ATYP_IPV4].pack('C')
      @bnd_addr = [0].pack('N')
      @bnd_port = [bnd_port].pack('n')
    end

    def serialize
      @ver + @rep + @rsv + @atyp + @bnd_addr + @bnd_port
    end
  end

  class SocksProxy  
    def initialize( options = {} )
      options = {
        port: 1080, 
        is_http_proxy: true, 
        system_proxy: nil, 
        log: true,             # CHECK - set to 'false' later
        log_level: "debug",
       # dns_source: "nameserver",      # CHECK - remove later
       # nameserver: "8.8.8.8"
      }.merge(options)       # merge (and overwrite) the options passed by user over the defaults
      
      @port = options[:port]
      @is_http_proxy = options[:is_http_proxy]
      @dns_source = options[:dns_source] # can be nil, "nameserver" or "web"
      @nameserver = options[:nameserver] # needs to be provided if dns_source = "nameserver"
      
      init_logger(options[:log], options[:log_level]) # instantiate a log object for logging
      
      @log.debug "Socks Proxy initialized with options: #{options}"

      if not options[:system_proxy].nil?
        @system_proxy = options[:system_proxy].split(':') 
        @system_proxy_addr = @system_proxy[0]
        @system_proxy_port = @system_proxy[1]
        @log.info "Sending all incoming requests to proxy => #{options[:system_proxy]}"
      end
      
      tcp_proxy_server = TCPServer.new('0.0.0.0', @port) # this is the non-ssl TCP server
      
      sslContext = OpenSSL::SSL::SSLContext.new
      sslContext.cert = OpenSSL::X509::Certificate.new(File.open("#{LIB_DIR}/certs/server.crt"))
      sslContext.key = OpenSSL::PKey::RSA.new(File.open("#{LIB_DIR}/certs/server.key"))
      @proxy_server = OpenSSL::SSL::SSLServer.new(tcp_proxy_server, sslContext)

      # don't immediately start TLS, Server will upgrade to TLS if it sees a clientHello handshake
      # by the client.
      @proxy_server.start_immediately = false 

      @log.info "Socks proxy listening on port #{@port}"

      @mutex = Mutex.new
      @thread_count = @tid = 0
      @threads = { }
    end

    def stats
      return @thread_count, @tid, @threads
    end

    def start(block = nil)
      @block = block
      #client = @proxy_server.accept
      #port, ip = Socket.unpack_sockaddr_in(client.getpeername)
      #puts "Connection from ip=#{ip} and port=#{port}"
      
      # handle_socks_connection client
      
      #begin
      loop do
        Thread.start(@proxy_server.accept) do |client|
          port, ip = Socket.unpack_sockaddr_in(client.io.getpeername)
          #puts "Connection request from ip=#{ip}:#{port}..."
          @mutex.synchronize {
            @thread_count += 1
            @tid += 1            # the unique thread id
            Thread.current['tid'] = @tid   # preserve the tid into thread's local variable
            @threads[@tid] = { client_ip: ip, client_port: port }
          }
          # puts ("Current Active Threads: #{@thread_count}, This is thread: #{@tid}")
          handle_socks_connection client
        end
      end
      #end
    end
    
    def handle_socks_connection(client)
      if socks_handshake(client)
        handle_socks_request(client) 
        
        current_tid = s_ip = s_port = c_ip = c_port = ""
        # connection closed - update data structures
        @mutex.synchronize {
          current_tid = Thread.current['tid']
          current_thread = @threads[current_tid]
          s_ip = current_thread[:server_ip]
          s_port = current_thread[:server_port]
          c_ip = current_thread[:client_ip]
          c_port = current_thread[:client_port]
          @thread_count -= 1
          @threads.delete(current_tid) # delete key
        }
      @log.debug "Closing connection between #{s_ip}:#{s_port} - #{c_ip}:#{c_port} (thread #{current_tid})\nActive connections now: #{@thread_count}\n"
      end
      client.close
    end
    
    
    # Refer RFC 1928 for complete details
    # 3 steps:
    # 1.) Client provides supported auth methods
    # 2.) Server chooses one (NOAUTH in this case)
    # 3.) Thats it :)
    def socks_handshake(client)
      # print(client, " is accepted\n")
      
      # first three bytes sent in socks handshake identify  VER | NMETHODS | METHODS respectively
      socks_version = client.read(1).unpack('C').first
      #puts "First byte (expected = 5) value: #{socks_version} class = #{socks_version.class}"
      
      return false, "SocksV5 protocol not detected... handshake failed" if socks_version != 5
      
      nmethods = client.read(1).unpack('C').first
      #puts "Number of methods = #{nmethods}"

      methods=[]
      nmethods.times do |method|
        methods <<  client.read(1).unpack('C').first
      end
      # Currently only method supported is 00 (NOAUTH)
      #puts "Methods supported: #{methods}"

      return false, "Supported auth method NOAUTH not present" if not methods.include?(0)
      # puts "version is 5 and methods is cool... Return the only selected method we support"
      # Send 05 00 indicating protocol version and auth method code respectively
      # puts "sending..."
      socks_version = [SOCKS_VER].pack('C')
      method = [AUTH_METHOD_NOAUTH].pack('C')
      handshake_reply = socks_version + method
      # puts "method = '#{handshake_reply.length}' and ver = '#{socks_version}' and #{SOCKS_VER}"
      num_bytes_sent = client.io.send(handshake_reply, 0)
      #puts "sent #{num_bytes_sent} bytes: #{handshake_reply.inspect}"  
      return true
    end

    def handle_socks_request(client)
      # SOCKS5 command request. First 4 bytes being: ver, cmd, rsv, atyp
      request_header = client.read(4).unpack('CCCC')
      atyp = request_header[3]
      @log.debug "atyp = #{atyp}"
      case atyp
      when 1                                        # IP V4 address: X'01'
        request_body_len = 4 + 2   # (4 byte IP addr, 2 byte port)
        request_body_fmt_str = 'Nn' 
        request_body = client.read(request_body_len).unpack(request_body_fmt_str)
      when 3                                        # DOMAINNAME: X'03'
        domain_name_len = client.read(1).unpack('C')   # first octet is the length of domain name (n)
        domain_name = client.read(domain_name_len.first).unpack('A*')[0] # query next n octets to fetch the domain name
        port = client.read(2).unpack('n').first
        ip = dns_lookup(domain_name, {source: @dns_source, ns: @nameserver}) # perform the DNS lookup and return back the result
        @log.debug "ATYP=03 (Domainname) received for domain: #{domain_name}. Resolved to #{ip}:#{port}"
        request_body = [ip, port]
      when 4                                        # IP V6 address: X'04'
        request_body_len = 16 + 2   # (16 byte IP addr, 2 byte port)
        request_body_fmt_str = 'Qn' #CHECK - This won't work as of now- we need a way to convert this into 64 bit network endian number
        request_body = client.read(request_body_len).unpack(request_body_fmt_str)
      end

      #puts "requesting #{request_body_len} bytes with format string '#{request_body_fmt_str}'"
      request = SocksRequest.new(request_header + request_body) # create socks request object

      #puts "request is #{request.inspect}"
      
      if @system_proxy # an upstream proxy provided by user
        dst_addr_str = @system_proxy_addr ; dst_port = @system_proxy_port
      else
        dst_addr_str = request.dst_addr_str ; dst_port = request.dst_port
      end
      
      # Connect to the host requested by client
      begin
        server = TCPSocket.open(dst_addr_str, dst_port)
      rescue
        puts "connection to server #{dst_addr_str}:#{dst_port} failed...\nError: #{$!}"
      end
      #puts "opening connection to #{dst_addr_str}:#{dst_port}... server = #{server.inspect}"

      @mutex.synchronize{
        server_details = { server_ip: dst_addr_str, server_port: dst_port}

        # The original server is the one requested by the client (browser). eg. ip corresponding to google.com 
        # This will be different from the server_details only for HTTPS connections in which case 
        # server_details is just the address of the upstream proxy server
        puts request.inspect
        original_server_details = { original_server_ip: request.dst_addr_str, original_server_port: request.dst_port}

        #puts server_details.inspect
        @threads[Thread.current['tid']].merge!(server_details)
        @threads[Thread.current['tid']].merge!(original_server_details)

       # puts "Thread merged = new hash = #{@threads[Thread.current['tid']]}"
      }
      
      response = SocksResponse.new(@port)
      #puts "sending serialized response= #{response.serialize.inspect}"
      num_bytes_sent = client.io.send(response.serialize, 0)
      #puts "bytes sent = #{num_bytes_sent}"
      
      # start proxying(middling) the data between the client and server
      proxy(client, server, &@block)
    end

    # Act as a simple proxy between client and server
    def proxy(client, tcp_server, &block)

      this_thread = @threads[Thread.current['tid']]
      s_ip = this_thread[:server_ip]
      s_port = this_thread[:server_port]
      s_ip_port = "#{s_ip}:#{s_port}"
      
      o_s_ip = this_thread[:original_server_ip]
      o_s_port = this_thread[:original_server_port]
      o_s_ip_port = "#{o_s_ip}:#{o_s_port}"
      
      c_ip = this_thread[:client_ip]
      c_port= this_thread[:client_port]
      c_ip_port = "#{c_ip}:#{c_port}"

      ssl = false                 # a flag which stores if the connection is SSL(HTTPS)
      #peek a couple (6 for SSL3, TLS 1.1/2/3) bytes and determine if this is a SSL ClientHello
      first_six_byte = client.io.recv(6, Socket::MSG_PEEK) # DOC:: client.recv for TCP sockets, client.io.recv for SSLsocket
      if is_ssl_handshake?(first_six_byte)         
        ssl = true
        # upgrade the socks_proxy <-> client/browser tcp socket to ssl 
        # client/browser will be presented a SSL warning/exception at this point
        client.accept

        # prepare the server
        # also connect to the server over ssl (upgrade socks_proxy<->server to SSL)
        context = OpenSSL::SSL::SSLContext.new
        context.ca_file = 'ca_cert.pem'
        context.verify_mode = OpenSSL::SSL::VERIFY_NONE
        
        # == support for upstream HTTP proxies ==
        # if there is a upstream HTTP proxy then pass the HTTP CONNECT command
        # for it to make a TCP tunnel to the target server
        if @system_proxy and @is_http_proxy
          tcp_server.write "CONNECT #{o_s_ip_port} HTTP/1.0\r\n\r\n"
          
          # the (ideal) response should be something like "HTTP/1.1 200 Connection established"
          connect_response = tcp_server.readpartial(64) 
          puts "connect_reponse to #{o_s_ip_port} is #{connect_response}"
        end
        
        # http_proxy has presumably created the tunnel to end(original) web-server, 
        # connect to http proxy as a SSL client now
        server  = OpenSSL::SSL::SSLSocket.new tcp_server, context
        server.connect
      else
        server = tcp_server # server is simple (non-ssl) tcp server socket
      end
      
      # Read client/server socket (whichever is readable) and relay
      # the data to server/client until any one of them ends connection (sends 0 byte)
      while true
        rw_sockets = IO.select([client, server])
        # puts "select returned #{rw_sockets.inspect}"
        readable = rw_sockets[0]
        readable.each do |socket|
          if socket == client   # read from client, send to server
            #puts "client is readable... getting request and sending to server"
            request = client.readpartial(4096)
            message = { 
              data: request,
              from: :client,
              from_ip: c_ip_port,
              to_ip: s_ip_port,
              tid: @tid,
              ssl: ssl,
              size: request.length
            }
            if block_given? then yield message else HexDump.print(request) end
            return if request.length <= 0
            num_bytes_sent = server.write request
          else                  # read from server, send to client
            #puts "server is readable... getting response and sending to client"
            response = server.readpartial(4096)
            message = { 
              data: response,
              from: :server,
              from_ip: s_ip_port,
              to_ip: c_ip_port,
              tid: @tid,
              ssl: ssl,
              size: response.length
            }
            if block_given? then yield message else HexDump.print(response) end
            return if response.length <= 0
            client.write response
          end
        end
      end
    end # proxy method ends

    # Initialize the logger
    # if logging is not requested (write_log = false) then create a 
    # dummy @log object so that all the logging calls in the code do 
    # not error out
    def init_logger(write_log, log_level)

      if not write_log     # logging to a log file is NOT requested
        @log = Object.new  # create a dummy @log object
        def @log.debug(msg) end # then make @log respond to the usual log methods
        def @log.info(msg) end  # This will ensure that all the @log statements
        def @log.warn(msg) end  # don't really do anything when called
        def @log.error(msg) end
        def @log.fatal(msg) end
        return 
      end
      
      # create a @log instance if logging is requested
      case log_level.downcase
      when "debug"
        level = Logger::DEBUG
      when "info"
        level = Logger::INFO
      when "warn"
        level = Logger::WARN
      when "error"
        level = Logger::ERROR
      when "fatal"
        level = Logger::FATAL
      else
        level = Logger::DEBUG
      end

      @log = Logger.new('socks_proxy.log')
      @log.level = level
      @log.formatter = proc do |severity, datetime, progname, msg|
        "[#{datetime.strftime('%Y-%m-%d %H:%M:%S.%5N')}]" +  '%6s' % [severity] + ": #{msg}\n"
      end
    end # init_logger method end
    
    # look at the 6 bytes and check if these are the first 6 bytes of 
    # a ClientHello SSL handshake
    # refer RFC or http://security.stackexchange.com/a/34783 for implementation details
    def is_ssl_handshake?(b)
      bytes = b.unpack('C*')
      if bytes[0]==22 and                       # SSL Handskake byte
          bytes[1]==3 and                       # SSL version number
          (0..5).include?(bytes[2]) and         # 0,1,2,3 respectively for SSL 3.0, TLS 1.0, TLS 1.1 and TLS 1.2
          bytes[5]==1
        return true
      else                  # not a SSL handshake
        return false  
      end
    end # is_ssl_handshake? method end
    
    # performs a DNS lookup for the domain name and returns the IP address
    # which the domain name resolved to. Options define where to resolve domain name from
    # eg. resolution using defaults, resolution using an specific DNS server, Webservice etc.
    def dns_lookup(domain_name, options = {})
      @log.info "Resolving domain #{domain_name} with options: #{options}"
      ip_str = ""
      case options[:source]
      when nil               # resolve using default nameserver
        ip_str = Resolv.getaddress domain_name
        @log.debug "Using default nameserver..."
      when "nameserver"      # resolve using the specific nameserver
        @log.debug "using nameserver #{options[:ns]}"
        Resolv::DNS.open({nameserver: [options[:ns]]}) do |r|
          ip_str = (r.getaddress domain_name).to_s
        end
        @log.debug "Using nameserver: #{options['ns']}..."
      when "web"             # resolve using the statdns REST api  useful in cases  where local resolution isn't available
        uri = URI.parse("http://api.statdns.com/#{domain_name}/a")
        
        if @system_proxy and @is_http_proxy # use upstream http proxy if provided
          http = Net::HTTP::Proxy(@system_proxy_addr, @system_proxy_port)
        else 
          http = Net::HTTP
        end
        response = JSON.parse((http.get_response(uri)).body)
        ip_str = response["answer"][-1]["rdata"]
        @log.debug "Using statdns web API..."
      end
      @log.debug "#{domain_name} resolves to IP: #{ip_str}"
      ip = Proxy::ip_dotted_to_dec(ip_str)
    end # dns_lookup method end
    
  end # SocksProxy class ends
  
  # --- Module methods available to all the classes ---

  # convert IP address in decimal to dotted notation
  def self.ip_dec_to_dotted(ip)
    octets = []
    4.times do
      octets << ip % 256
      ip = ip / 256
    end
    ip_str = octets[3].to_s + "." + octets[2].to_s + "." +  octets[1].to_s + "." + octets[0].to_s
  end

  # convert IP address in dotted notation to decimal ---
  def self.ip_dotted_to_dec(ip_str)
    octets = ip_str.split('.')
    ip_decimal =   
      octets[0].to_i() *256*256*256 +
      octets[1].to_i() *256*256 +
      octets[2].to_i() *256 +
      octets[3].to_i()
  end
    
end # SocksProxy module ends
