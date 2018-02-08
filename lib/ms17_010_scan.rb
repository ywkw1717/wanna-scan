require 'socket'
require_relative 'negotiate_protocol'
require_relative 'session_setup_andx'
require_relative 'tree_connect_andx'
require_relative 'peek_named_pipe'

class Ms17010Scan
  def initialize(logger: STDERR)
    @logger          = logger
    @port            = 445
    @vulnerable_host = []
    @m               = Mutex.new
  end

  def start(ip)
    host               = ip
    sock               = TCPSocket.open(host, @port)
    negotiate_protocol = NegotiateProtocol.new
    session_setup_andx = SessionSetupAndX.new

    sock.write(negotiate_protocol.request)
    begin
      # Don't use "gets" method. If there is '\n' in the response, "gets" method takes it as EOF.
      while select [sock], nil, nil, 0.5
        negotiate_protocol.response = sock.readpartial(4096).unpack('C*')
      end

      sock.write(session_setup_andx.request)
      while select [sock], nil, nil, 0.5
        session_setup_andx.response = sock.readpartial(4096).unpack('C*')
      end

      tree_connect_andx = TreeConnectAndX.new(
        session_setup_andx.user_id,
        host.unpack('C*').map { |s| '\x' + s.to_s(16) }.join,
        host.length.to_i
      )

      sock.write(tree_connect_andx.request)
      while select [sock], nil, nil, 0.5
        tree_connect_andx.response = sock.readpartial(4096).unpack('C*')
      end

      peek_named_pipe = PeekNamedPipe.new(tree_connect_andx.tree_id, session_setup_andx.user_id)
      sock.write(peek_named_pipe.request)
      while select [sock], nil, nil, 0.5
        peek_named_pipe.response = sock.readpartial(4096).unpack('C*')
      end

      @m.synchronize do
        @vulnerable_host << host if peek_named_pipe.nt_status == 'c0000205'
      end
    rescue => e
      # puts e
    ensure
      sock.close
    end
  end

  def vulnerable_host
    @vulnerable_host
  end
end
