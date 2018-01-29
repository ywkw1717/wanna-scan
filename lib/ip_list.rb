class IPList
  def initialize
    ip_command = `arp -a -n`
    @ip_list    = []

    ip_command.each_line do |s|
      @ip_list.push(s.slice(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/))
    end
  end

  def ip_list
    @ip_list
  end
end
