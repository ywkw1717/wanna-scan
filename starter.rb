require_relative 'lib/ms17_010_scan'
require_relative 'lib/double_pulsar_scan'
require_relative 'lib/host_scan.rb'
require_relative 'lib/port_scan.rb'

host_scan = HostScan.new
port_scan = PortScan.new

# Search host opend 445 port
threads = []
host_scan.ip_list.each { |s| threads << Thread.new { port_scan.start(s) } }
threads.each(&:join)

# MS17-010 and DoublePulsar check
threads = []
port_scan.open_445_list.each { |ip| threads << Thread.new {
  ms17_010_scan = Ms17010Scan.new(ip)
  ms17_010_scan.start
  double_pulsar_scan = DoublePulsarScan.new(ip)
  double_pulsar_scan.start
} }
threads.each(&:join)
