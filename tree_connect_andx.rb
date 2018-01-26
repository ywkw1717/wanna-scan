class TreeConnectAndX
  def initialize(user_id, ip)
    @request  = []
    @response = []

    @netbios_session_service = [
      '\x00', # Message Type: Session message (0x00)
      '\x00\x00\x45' # Length
    ]

    @smb_header = [
      '\xff\x53\x4d\x42', # Server Component: SMB
      '\x75', # SMB Command: Tree Connect AndX (0x75)
      '\x00', # Error Class: Success (0x00)
      '\x00', # Reserved
      '\x00\x00', # Error Code: No Error
      '\x18', # Flags
      '\x01\x28', # Flags2
      '\x00\x00', # Process ID High
      '\x00\x00\x00\x00\x00\x00\x00\x00', # Signature
      '\x00\x00', # Reserved
      '\x00\x00', # Tree ID
      '\xf0\x58', # Process ID
      user_id, # User ID
      '\x38\xd8' # Multiplex ID
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
