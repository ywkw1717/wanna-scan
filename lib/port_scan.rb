class PortScan
  def initialize
    @open_445_list = []
  end

  def start(ip)
    result = `nmap -n -p 445 -PN -open #{ip} |grep open`
    return if result.empty?
    @open_445_list.push(ip)
  end

  def open_445_list
    @open_445_list.sort_by! { |s| s.split(".").map(&:to_i) }
    @open_445_list
  end
end
