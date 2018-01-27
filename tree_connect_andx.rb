require_relative 'smb_header'

class TreeConnectAndX < SMBHeader
  def initialize(user_id, ip)
    @request  = []
    @response = []

    @netbios_session_service = [
      '\x00', # Message Type: Session message (0x00)
      '\x00\x00\x45' # Length
    ]

    @tree_connect_andx_request = [
      '\x04', # Word Count (WCT)
      '\xff', # AndXCommand: No further commands (0xff)
      '\x00', # Reserved
      '\x00\x00', # AndXOffset
      '\x00\x00', # Flags
      '\x01\x00', # Password Length
      '\x1a\x00', # Byte Count (BCC)
      '\x00', # Password
      '\x5c\x5c', # \\
      ip, # IP Address
      '\x5c\x49\x50\x43\x24\x00', # \IPC$
      '\x3f\x3f\x3f\x3f\x3f\x00'
    ]

    @tree_connect_andx_response = []
    @tree_id = []

    super(smb_command: '\x75', user_id: user_id)
    make_request
  end

  def request
    @request.join
  end

  def response=(data)
    parse_response(data)
  end

  def response
    @response
  end

  def tree_id
    @tree_id.join
  end

  def make_request
    tmp = []

    tmp.concat(@netbios_session_service)
    tmp.concat(@smb_header)
    tmp.concat(@tree_connect_andx_request)
    tmp = tmp.join.split("\\x")
    tmp.shift # delete first element

    tmp.map do |s|
      @request.push([s.hex].pack("C*"))
    end
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header = response[4..35]
    @tree_connect_andx_response = response[36..-1]

    @tree_id = @smb_header[-8..-7].map {|s| '\x' + s.to_s(16)}
  end
end
