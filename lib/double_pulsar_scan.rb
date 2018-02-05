require_relative 'smb'
require_relative 'negotiate_protocol'
require_relative 'session_setup_andx'
require_relative 'tree_connect_andx'

class DoublePulsarScan < SMB
  def initialize
    @logger          = STDERR
    @port            = 445
    @m               = Mutex.new
    @vulnerable_host = []

    @trans2_request = [
      '\x0f', # Word Count (WCT)
      '\x0c\x00', # Total Parameter Count
      '\x00\x00', # Total Data Count
      '\x01\x00', # Max Parameter Count
      '\x00\x00', # Max Data Count
      '\x00', # Max Setup Count
      '\x00', # Reserved
      '\x00\x00', # Flags
      '\xa6\xd9\xa4\x00', # Timeout: 3 hours, 3.622 seconds
      '\x00\x00', # Reserved
      '\x0c\x00', # Parameter Count
      '\x42\x00', # Parameter Offset
      '\x00\x00', # Data Count
      '\x4e\x00', # Data Offset
      '\x01', # Setup Count
      '\x00', # Reserved
      '\x0e\x00', # Subcommand: SESSION_SETUP
      '\x00\x00', # Byte Count (BCC)
      '\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' # other data
    ]
  end

  def start(ip)
    host               = ip
    sock               = TCPSocket.open(host, @port)
    negotiate_protocol = NegotiateProtocol.new
    session_setup_andx = SessionSetupAndX.new

    sock.write(negotiate_protocol.request)

    begin
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
        (host.length.to_i + 58).to_s(16)
      )

      sock.write(tree_connect_andx.request)
      while select [sock], nil, nil, 0.5
        tree_connect_andx.response = sock.readpartial(4096).unpack('C*')
      end

      super(
        length: '\x00\x00\x4f',
        smb_command: '\x32',
        flags2: '\x07\xc0',
        tree_id: tree_connect_andx.tree_id,
        user_id: session_setup_andx.user_id,
        multiplex_id: '\x41\x00'
      )

      make_request(@netbios_session_service, @smb_header, @trans2_request)
    rescue => e
      # puts e
    end

    sock.write(@request)

    begin
      while select [sock], nil, nil, 0.5
        parse_response(sock.readpartial(4096).unpack('C*'))
      end

      if @multiplex_id[0] == 81
        @vulnerable_host << host
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

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header              = response[4..35]
    @trans_response          = response[36..-1]
    @multiplex_id            = @smb_header[-2..-1]
  end
end
