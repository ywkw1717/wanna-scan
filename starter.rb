require_relative 'lib/ms17_010_scan'
require_relative 'lib/double_pulsar_scan'

# MS17-010 check
@ms17_010_scan = Ms17010Scan.new("10.10.10.10")
@ms17_010_scan.start

# DoublePulsar check
@double_pulsar_scan = DoublePulsarScan.new('10.10.10.10')
@double_pulsar_scan.start
