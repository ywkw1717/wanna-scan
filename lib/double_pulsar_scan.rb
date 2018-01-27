require_relative 'smb'
require_relative 'negotiate_protocol'
require_relative 'session_setup_andx'
require_relative 'tree_connect_andx'

class DoublePulsarScan < SMB
  def initialize(host)
    @logger = STDERR
    @host   = host
    @port   = 445
    @sock   = TCPSocket.open(@host, @port)

    @negotiate_protocol = NegotiateProtocol.new
    @session_setup_andx = SessionSetupAndX.new

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

    @logger.puts("\n[*] DoublePulsarScan start")

    @sock.write(@negotiate_protocol.request)
    @negotiate_protocol.response = @sock.readpartial(4096).unpack("C*")

    @sock.write(@session_setup_andx.request)
    @session_setup_andx.response = @sock.readpartial(4096).unpack("C*")

    @tree_connect_andx = TreeConnectAndX.new(@session_setup_andx.user_id, @host.unpack("C*").map {|s| '\x' + s.to_s(16)}.join)

    @sock.write(@tree_connect_andx.request)
    @tree_connect_andx.response = @sock.readpartial(4096).unpack("C*")

    super(length: '\x00\x00\x4f', smb_command: '\x32', flags2: '\x07\xc0', tree_id: @tree_connect_andx.tree_id, user_id: @session_setup_andx.user_id, multiplex_id: '\x41\x00')
    make_request(@netbios_session_service, @smb_header, @trans2_request)
  end

  def start
    @sock.write(@request)
    parse_response(@sock.readpartial(4096).unpack("C*"))

    if @multiplex_id[0] == 81 then
      @logger.puts "[+] " + @host + " has been infected with DoublePulsar"
    else
      @logger.puts "[-] DoublePulsar is not found"
    end

    @logger.puts("[*] DoublePulsarScan finish")
    @sock.close
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header              = response[4..35]
    @trans_response          = response[36..-1]

    @multiplex_id = @smb_header[-2..-1]
  end
end