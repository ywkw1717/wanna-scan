# Hey WannaCry FUCK YOU!
wanna-scan is a scanner to look for MS17-010 and DoublePulsar. wanna-scan can look for all computers of same network.

## Requirements
- ruby >= 2.4.0
- nmap >= 6.40
- arp-scan >= 1.8.1

## Install
```
$ git clone https://github.com/ywkw1717/wanna-scan
$ sudo apt-get install nmap
$ sudo apt-get install arp-scan
```

## Usage
```
Usage: ruby wanna_scan.rb [options] {value}

Options:
  -i [ip addr]  scan ip
  -I [nic]      scan nic
```

If you want to check one IP address
```ruby
$ ruby wanna_scan.rb -i 192.168.0.153
[*] MS17-010 Scan start
[+] 192.168.0.153 has a vulnerability of MS17-010
[*] MS17-010 Scan finish

[*] DoublePulsar Scan start
[-] DoublePulsar is not found
[*] DoublePulsar Scan finish
```

If you want to check all computers of same network
(In this case, "enp0s9" is device name of network interface card)
```ruby
$ ruby wanna_scan.rb -I enp0s9
[*] MS17-010 Scan start
[+] Vulnerability of MS17-010 list
192.168.0.153
[*] MS17-010 Scan finish

[*] DoublePulsar Scan start
[+] Infected with DoublePulsar list
nothing
[*] DoublePulsar Scan finish
```

# Information
Also, I made this program.

[https://github.com/ywkw1717/get_wanna_packet](https://github.com/ywkw1717/get_wanna_packet)
