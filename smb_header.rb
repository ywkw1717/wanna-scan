class SMBHeader
  def initialize(smb_command: '\x00', flags2: '\x01\x28', tree_id: '\x00\x00', user_id: '\x00\x00')
    @smb_header = [
      '\xff\x53\x4d\x42', # Server Component: SMB
      smb_command, # SMB Command: Negotiate Protocol
      '\x00', # Error Class: Success (0x00)
      '\x00', # Reserved
      '\x00\x00', # Error Code: No Error
      '\x18', # Flags
      flags2, # Flags2
      '\x00\x00', # Process ID High
      '\x00\x00\x00\x00\x00\x00\x00\x00', # Signature
      '\x00\x00', # Reserved
      tree_id, # Tree ID
      '\xf0\x58', # Process ID
      user_id, # User ID
      '\x38\xd8' # Multiplex ID
    ]

    @smb_header
  end
end
