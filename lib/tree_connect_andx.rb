require_relative 'smb'

class TreeConnectAndX < SMB
  def initialize(user_id, ip, len)
    super(length: '\x00\x00\x' + (len + 58).to_s(16), smb_command: '\x75', flags2: '\x01\x20', user_id: user_id)

    @tree_connect_andx_request = [
      '\x04', # Word Count (WCT)
      '\xff', # AndXCommand: No further commands (0xff)
      '\x00', # Reserved
      '\x00\x00', # AndXOffset
      '\x00\x00', # Flags
      '\x01\x00', # Password Length
      '\x' + (len + 15).to_s(16) + '\x00', # Byte Count (BCC)
      '\x00', # Password
      '\x5c\x5c', # \\
      ip, # IP Address
      '\x5c\x49\x50\x43\x24\x00', # \IPC$
      '\x3f\x3f\x3f\x3f\x3f\x00'
    ]

    make_request(@netbios_session_service, @smb_header, @tree_connect_andx_request)
  end

  def response=(data)
    parse_response(data)
  end

  def tree_id
    @tree_id
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header = response[4..35]
    @tree_connect_andx_response = response[36..-1]

    @tree_id = @smb_header[-8..-7].map { |s| '\x' + s.to_s(16) }.join
  end
end
