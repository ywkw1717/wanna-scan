class SessionSetupAndX
  def initialize
    @request  = []
    @response = []

    @netbios_session_service = [
      '\x00', # Message Type: Session message (0x00)
      '\x00\x00\x63' # Length
    ]

    @smb_header = [
      '\xff\x53\x4d\x42', # Server Component: SMB
      '\x73', # SMB Command: Session Setup AndX (0x73)
      '\x00', # Error Class: Success (0x00)
      '\x00', # Reserved
      '\x00\x00', # Error Code: No Error
      '\x18', # Flags
      '\x01\x20', # Flags2
      '\x00\x00', # Process ID High
      '\x00\x00\x00\x00\x00\x00\x00\x00', # Signature
      '\x00\x00', # Reserved
      '\x00\x00', # Tree ID
      '\xf0\x58', # Process ID
      '\x00\x00', # User ID
      '\x38\xd8' # Multiplex ID
    ]

    @session_setup_andx_request = [
      '\x0d', # Word Count (WCT)
      '\xff', # AndXCommand: No further commands (0xff)
      '\x00', # Reserved
      '\x00\x00', # AndXOffset
      '\xdf\xff', # Max Buffer
      '\x02\x00', # Max Mpx Count
      '\x01\x00', # VC Number
      '\x00\x00\x00\x00', # Session Key
      '\x00\x00', # ANSI Password Length
      '\x00\x00', # Unicode Password Length
      '\x00\x00\x00\xx00', # Reserved
      '\x40\x00\x00\x00', # Capabilities: 0x00000040, NT Status Codes
      '\x26\x00', # Byte Count (BCC)
      '\x00', # Account
      '\x2e\x00', # Primary Domain
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00', # Native OS: Windows 2000 2195
      '\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00' # Native LAN Manager:  Windows 2000 5.0
    ]

    @session_setup_andx_response = []
    @user_id = []

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

  def user_id
    @user_id.join
  end

  def make_request
    tmp = []

    tmp.concat(@netbios_session_service)
    tmp.concat(@smb_header)
    tmp.concat(@session_setup_andx_request)
    tmp = tmp.join.split("\\x")
    tmp.shift # delete first element

    tmp.map do |s|
      @request.push([s.hex].pack("C*"))
    end
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header = response[4..35]
    @session_setup_andx_response = response[36..-1]

    @user_id = @smb_header[-4..-3].map {|s| '\x' + s.to_s(16)}
  end
end
