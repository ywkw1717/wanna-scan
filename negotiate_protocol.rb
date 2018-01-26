class NegotiateProtocol
  def initialize
    @request  = []
    @response = []

    @netbios_session_service = [
      '\x00', # Message Type: Session message (0x00)
      '\x00\x00\x54' # Length
    ]

    @smb_header = [
      '\xff\x53\x4d\x42', # Server Component: SMB
      '\x72', # SMB Command: Negotiate Protocol (0x72)
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
      '\x00\x00', # User ID
      '\x38\xd8' # Multiplex ID
    ]

    @negotiate_protocol_request = [
      '\x00', # Word Count (WCT)
      '\x31\x00', # Byte Count (BCC)
      '\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00', # Dialect: LANMAN1.0
      '\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00', # Dialect: LM1.2X002
      '\x02\x4e\x54\x20\x4c\x41\x4e\x4d\x41\x4e\x20\x31\x2e\x30\x00', # Dialect: NT LANMAN 1.0
      '\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00' # Dialect: NT LM 0.12
    ]

    make_request
  end

  def request
    @request.join
  end

  def response=(data)
    @response = data
  end

  def response
    @response
  end

  def make_request
    tmp = []

    tmp.concat(@netbios_session_service)
    tmp.concat(@smb_header)
    tmp.concat(@negotiate_protocol_request)
    tmp = tmp.join.split("\\x")
    tmp.shift # delete first element

    tmp.map do |s|
      @request.push([s.hex].pack("C*"))
    end
  end
end
