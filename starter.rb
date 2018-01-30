require 'optparse'
require_relative 'lib/ms17_010_scan'
require_relative 'lib/double_pulsar_scan'
require_relative 'lib/host_scan.rb'
require_relative 'lib/port_scan.rb'

def scan_ip(ip)
  ms17_010_scan = Ms17010Scan.new(ip)
  ms17_010_scan.start
  double_pulsar_scan = DoublePulsarScan.new(ip)
  double_pulsar_scan.start
end

def usage
  puts <<-"EOS"
Usage: ruby starter.rb [options] {value}

Options:
   i [ip addr]  scan ip
  -I [nic]      scan nic
EOS
end

params = ARGV.getopts('i:I:')

if params["i"] && params["I"]
  puts "You can not specify both options.\n\n"
  usage
  return
elsif !params["i"] && !params["I"]
  usage
  return
end

# [TODO] check the input value?
ip = params["i"]
unless ip.nil?
  scan_ip(ip)
  return
end

# [TODO] check the input value?
host_scan = HostScan.new(params["I"])
port_scan = PortScan.new

# Search host opend 445 port
threads = []
host_scan.ip_list.each { |s| threads << Thread.new { port_scan.start(s) } }
threads.each(&:join)

# [TODO] output result in a file
# MS17-010 and DoublePulsar check
threads = []
port_scan.open_445_list.each { |ip| threads << Thread.new { scan_ip(ip) } }
threads.each(&:join)
