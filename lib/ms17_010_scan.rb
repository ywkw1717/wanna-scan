require 'socket'
require_relative 'negotiate_protocol'
require_relative 'session_setup_andx'
require_relative 'tree_connect_andx'
require_relative 'peek_named_pipe'

class Ms17010Scan
  def initialize(host, logger: STDERR)
    @logger             = logger
    @host               = host
    @port               = 445
    @sock               = TCPSocket.open(@host, @port)
    @negotiate_protocol = NegotiateProtocol.new
    @session_setup_andx = SessionSetupAndX.new

    @m = Mutex.new
  end

  def start
    @sock.write(@negotiate_protocol.request)

    begin
      # Don't use "gets" method. If there is '\n' in the response, "gets" method takes it as EOF.
      @negotiate_protocol.response = @sock.readpartial(4096).unpack("C*")

      @sock.write(@session_setup_andx.request)
      @session_setup_andx.response = @sock.readpartial(4096).unpack("C*")

      @tree_connect_andx = TreeConnectAndX.new(@session_setup_andx.user_id, @host.unpack("C*").map { |s| '\x' + s.to_s(16) }.join, (@host.length.to_i + 58).to_s(16))

      @sock.write(@tree_connect_andx.request)
      @tree_connect_andx.response = @sock.readpartial(4096).unpack("C*")

      @@peek_named_pipe = PeekNamedPipe.new(@tree_connect_andx.tree_id, @session_setup_andx.user_id)
      @sock.write(@@peek_named_pipe.request)
      @@peek_named_pipe.response = @sock.readpartial(4096).unpack("C*")

      @m.synchronize {
        logging
      }
    rescue => e
      @logger.puts("[*] MS17-010 Scan start")
      @logger.puts "[*] OS: #{@session_setup_andx.native_os}, IP: #{@host}"

      puts e

      @logger.puts("[*] MS17-010 Scan finish")
    ensure
      @sock.close
    end
  end

  def logging
    @logger.puts("[*] MS17-010 Scan start")
    @logger.puts "[*] OS: #{@session_setup_andx.native_os}, IP: #{@host}"

    if @@peek_named_pipe.nt_status == 'c0000205'
      @logger.puts "[+] " + @host + " has a vulnerability of MS17-010"
    else
      @logger.puts "[-] The vulnerability is not found"
    end

    @logger.puts("[*] MS17-010 Scan finish")
  end

  def session_setup_andx
    @session_setup_andx
  end

  def tree_connect_andx
    @tree_connect_andx
  end
end
