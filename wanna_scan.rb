require 'optparse'
require 'pathname'
require_relative 'lib/ms17_010_scan'
require_relative 'lib/double_pulsar_scan'
require_relative 'lib/host_scan.rb'
require_relative 'lib/port_scan.rb'

def usage
  <<~USAGE
    Usage: ruby wanna_scan.rb [options] {value}

    Options:
      -i [ip addr]           scan ip
      -I [interface]         scan interface
      -o [output directory]  output in the directory
  USAGE
end

def output(dir)
  return if dir.nil?

  date = Time.new.strftime('%Y%m%d-%H%M%S')
  path = Pathname.new(dir).join('wanna_scan_' + date + '.txt')

  File.open(path, 'w') do |f|
    f.puts(date)
    f.puts("[+] Vulnerability of MS17-010 list\n")
    @ms17_010_scan.vulnerable_host.each { |s| f.puts(s) }

    f.puts("\n[+] Infected with DoublePulsar list")
    @double_pulsar_scan.vulnerable_host.each { |s| f.puts(s) }
  end
end

params = ARGV.getopts('i:I:o:')
if params['i'] && params['I']
  puts "You can not specify many options.\n\n"
  puts usage
  exit
elsif !params['i'] && !params['I']
  puts usage
  exit
end

# [TODO] check the input value?
ip = params['i']
unless ip.nil?
  port_scan = PortScan.new
  port_scan.start(ip)

  if port_scan.open_445_list.empty?
    puts("#{ip} is not opening 445 port.")
    exit
  end

  puts('[*] MS17-010 Scan start')

  @ms17_010_scan = Ms17010Scan.new
  @ms17_010_scan.start(ip)

  if @ms17_010_scan.vulnerable_host.empty?
    puts '[-] The vulnerability is not found'
  else
    puts("[+] #{@ms17_010_scan.vulnerable_host[0]} has a vulnerability of MS17-010")
  end

  puts('[*] MS17-010 Scan finish')

  puts("\n[*] DoublePulsar Scan start")

  @double_pulsar_scan = DoublePulsarScan.new
  @double_pulsar_scan.start(ip)

  if @double_pulsar_scan.vulnerable_host.empty?
    puts('[-] DoublePulsar is not found')
  else
    puts "[+] #{@double_pulsar_scan.vulnerable_host[0]} has been infected with DoublePulsar"
  end

  puts("[*] DoublePulsar Scan finish\n\n")

  output(params['o'])
  exit
end

# [TODO] check the input value?
host_scan = HostScan.new(params['I'])
port_scan = PortScan.new
threads   = []

# Search host opend 445 port
host_scan.ip_list.each do |s|
  threads << Thread.new do
    port_scan.start(s)
  end
end
threads.each(&:join)

# MS17-010 scan
puts('[*] MS17-010 Scan start')
@ms17_010_scan = Ms17010Scan.new

port_scan.open_445_list.each do |host|
  threads << Thread.new do
    @ms17_010_scan.start(host)
  end
end
threads.each(&:join)

puts("[+] Vulnerability of MS17-010 list\n")
if @ms17_010_scan.vulnerable_host.empty?
  puts('nothing')
else
  puts @ms17_010_scan.vulnerable_host
end
puts('[*] MS17-010 Scan finish')

# DoublePulsar scan
puts("\n[*] DoublePulsar Scan start")
@double_pulsar_scan = DoublePulsarScan.new

port_scan.open_445_list.each do |host|
  threads << Thread.new do
    @double_pulsar_scan.start(host)
  end
end
threads.each(&:join)

puts('[+] Infected with DoublePulsar list')
if @double_pulsar_scan.vulnerable_host.empty?
  puts('nothing')
else
  puts @double_pulsar_scan.vulnerable_host
end
puts("[*] DoublePulsar Scan finish\n\n")

output(params['o'])
