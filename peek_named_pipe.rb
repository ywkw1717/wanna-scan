require_relative 'smb'

class PeekNamedPipe < SMB
  def initialize(tree_id, user_id)
    super(length: '\x00\x00\x4a', smb_command: '\x25', tree_id: tree_id, user_id: user_id)

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

    make_request(@netbios_session_service, @smb_header, @trans_request)
  end

  def response=(data)
    parse_response(data)
  end

  def nt_status
    @nt_status
  end

  def parse_response(response)
    @netbios_session_service = response[0..3]
    @smb_header              = response[4..35]
    @trans_response          = response[36..-1]

    @nt_status = @smb_header[5..8].map {|s| s.to_s(16).rjust(2, "0")}.reverse.join
  end
end
