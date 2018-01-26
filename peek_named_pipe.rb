class PeekNamedPipe
  def initialize(tree_id, user_id)
    @request  = []
    @response = []

    @netbios_session_service = [
      '\x00', # Message Type: Session message (0x00)
      '\x00\x00\x4a' # Length
    ]

    @smb_header = [
      '\xff\x53\x4d\x42', # Server Component: SMB
      '\x25', # SMB Command: Trans (0x25)
      '\x00', # Error Class: Success (0x00)
      '\x00', # Reserved
      '\x00\x00', # Error Code: No Error
      '\x18', # Flags
      '\x01\x28', # Flags2
      '\x00\x00', # Process ID High
      '\x00\x00\x00\x00\x00\x00\x00\x00', # Signature
      '\x00\x00', # Reserved
      tree_id, # Tree ID
      '\xf0\x58', # Process ID
      user_id, # User ID
      '\x38\xd8' # Multiplex ID
    ]

    @trans_request = [
      '\x10', # Word Count (WCT)
      '\x00\x00', # Total Parameter Count
      '\x00\x00', # Total Data Count
      '\xff\xff', # Max Parameter Count
      '\xff\xff', # Max Data Count
      '\x00', # Max Setup Count
      '\x00', # Reserved
      '\x00\x00', # Flags
      '\x00\x00\x00\x00', # Timeout: Return Immediately (0)
      '\x00\x00', # Reserved
      '\x00\x00', # Parameter Count
      '\x4a\x00', # Parameter Offset
      '\x00\x00', # Data Count
      '\x4a\x00', # Data Offset
      '\x02', # Setup Count
      '\x00', # Reserved
      '\x23\x00', # Function: PeekNamedPipe
      '\x00\x00', # FID
      '\x07\x00', # Byte Count (BCC)
      '\x5c\x50\x49\x50\x45\x5c\x00' # Transaction Name: \PIPE\
    ]

    @trans_response = []
    @nt_status = []

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

  def nt_status
    @nt_status
  end

  def make_request
    tmp = []

    tmp.concat(@netbios_session_service)
    tmp.concat(@smb_header)
    tmp.concat(@trans_request)
    tmp = tmp.join.split("\\x")
    tmp.shift # delete first element

    tmp.map do |s|
      @request.push([s.hex].pack("C*"))
    end
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header              = response[4..35]
    @trans_response          = response[36..-1]

    @nt_status = @smb_header[5..8].map {|s| s.to_s(16).rjust(2, "0")}.reverse.join
  end
end
