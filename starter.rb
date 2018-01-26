require_relative 'ms17_010_scan'

@ms17_010_scan = Ms17010Scan.new("10.10.10.10")
@ms17_010_scan.start
