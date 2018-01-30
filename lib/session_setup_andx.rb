require_relative 'smb'

class SessionSetupAndX < SMB
  def initialize
    super(length: '\x00\x00\x63', smb_command: '\x73', flags2: '\x01\x20')

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

    make_request(@netbios_session_service, @smb_header, @session_setup_andx_request)
  end

  def response=(data)
    parse_response(data)
  end

  def user_id
    @user_id
  end

  def native_os
    @native_os
  end

  def parse_response(response)
    @netbios_session_service     = response[0..3]
    @smb_header                  = response[4..35]
    @session_setup_andx_response = response[36..-1]

    @user_id   = @smb_header[-4..-3].map { |s| '\x' + s.to_s(16) }.join
    @native_os = []

    @session_setup_andx_response[9..-1].map do |s|
      break if s.zero?
      @native_os << s.chr
    end

    @native_os = @native_os.join
  end
end
