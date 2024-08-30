## rsubdomain
Implementation principle reference [ksubdomain](https://github.com/knownsec/ksubdomain)

## Why
for learn rust and network programming


## Usage
use before need install libpcap or npcap.

```
$ git clone https://github.com/o0x1024/rsubdomain
$ cd rsubdomain
$ cargo build --release
```

```
root@test:~/workplace/rsubdomain/target/debug# ./rsubdomain  -d sf-express.com -p 
["sf-express.com"]
test domain:DcT8.example.com
EthTable { src_ip: 172.28.11.191, device: "wlp2s0", src_mac: b0:a4:60:ec:fc:2a, dst_mac: 68:a8:28:2f:d7:03 }
es.sf-express.com =>  114.132.164.112
monitor.sf-express.com =>  114.132.161.48
css.sf-express.com =>  114.132.198.68
boss.sf-express.com =>  114.132.161.48
webdev.sf-express.com =>  43.139.34.90
ctc.sf-express.com =>  183.62.100.79
canada.sf-express.com =>  114.132.161.48
sites.sf-express.com =>  119.91.65.14
nagios.sf-express.com =>  175.178.246.65
ntp.sf-express.com =>  218.17.224.69
labs.sf-express.com =>  114.132.161.48
fm.sf-express.com =>  139.159.229.166
developers.sf-express.com =>  114.132.198.68
done
```

```
root@test:~/workplace/rsubdomain/target/debug# ./rsubdomain
A tool for brute-forcing subdomains

Usage: rsubdomain [OPTIONS]

Options:
  -d, --domain <DOMAIN>        need scan domain
  -l, --list-network           list network
  -r, --resolvers <RESOLVERS>  resolvers path,use default dns on default
  -p, --print-status           print result
  -s, --slient                 slient
  -f, --file <FILE>            dic path
  -h, --help                   Print help
  -V, --version                Print version
root@test:~/workplace/rsubdomain/target/debug# ./rsubdomain  -d example.com -p --slient
```



## Windows
There are three requirements for building on Windows:

You must use a version of Rust which uses the MSVC toolchain
You must have [WinPcap](https://www.winpcap.org/) or [npcap](https://nmap.org/npcap/) installed (tested with version WinPcap 4.1.3) (If using npcap, make sure to install with the "Install Npcap in WinPcap API-compatible Mode")
You must place `Packet.lib` from the [WinPcap Developers](https://www.winpcap.org/devel.htm) pack in a directory named `lib`, in the root of this repository. Alternatively, you can use any of the locations listed in the `%LIB%/$Env:LIB` environment variables. For the 64 bit toolchain it is in `WpdPack/Lib/x64/Packet.lib`, for the 32 bit toolchain, it is in `WpdPack/Lib/Packet.lib`.
