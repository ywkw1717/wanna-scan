class IPList
  def initialize
    ip_list = `arp -a -n |grep -o -e "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+"`
  end
end
