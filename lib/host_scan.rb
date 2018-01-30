class HostScan
  def initialize
    ip_command = `sudo arp-scan -I enp0s9 -l`
    @ip_list   = []

    ip_command.each_line do |s|
      ip = s.slice(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
      next if ip.nil?

      @ip_list.push(ip)
    end
  end

  def ip_list
    @ip_list
  end
end
