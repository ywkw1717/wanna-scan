require 'socket'
require_relative 'negotiate_protocol'
require_relative 'session_setup_andx'
require_relative 'tree_connect_andx'
require_relative 'peek_named_pipe'

def ms17_010_scan
  host = '10.10.10.10'
  port = 445
  sock = TCPSocket.open(host, port)

  negotiate_protocol = NegotiateProtocol.new
  session_setup_andx = SessionSetupAndX.new

  sock.write(negotiate_protocol.request)

  # Don't use "gets" method. If there is '\n' in the response, "gets" method takes it as EOF.
  negotiate_protocol.response = sock.readpartial(4096).unpack("C*")

  sock.write(session_setup_andx.request)
  session_setup_andx.response = sock.readpartial(4096).unpack("C*")
  tree_connect_andx = TreeConnectAndX.new(session_setup_andx.user_id, host.unpack("C*").map {|s| '\x' + s.to_s(16)}.join)

  sock.write(tree_connect_andx.request)
  tree_connect_andx.response = sock.readpartial(4096).unpack("C*")

  peek_named_pipe = PeekNamedPipe.new(tree_connect_andx.tree_id, session_setup_andx.user_id)
  sock.write(peek_named_pipe.request)
  peek_named_pipe.response = sock.readpartial(4096).unpack("C*")

  if peek_named_pipe.nt_status == 'c0000205' then
    p "message"
  end

  sock.close
end

ms17_010_scan
