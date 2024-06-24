# udp-link

## Description

This is a simple UDP link layer implementation. It is intended to be used as a ssh proxy to make ssh-session more stable in case of unstable network connection and changing IP-addresses.

## Usage

```
ssh -o ProxyCommand="udp-link %r@%h %p" user@host
```
or in case of connection through a jump server:
```
ssh -o ProxyCommand "udp-link --target=%h:%p jumpserver" user@host
```
It is convenient to add this to your ~/.ssh/config:
```
Host your.domain
    ProxyCommand "udp-link %r@%h %p"
```

## Installation

On Ubuntu you can install udp-link from [deb-package](https://github.com/pgul/udp-link/releases/latest).
On other systems such as MacOS, FreeBSD or other Linux distributives, install it from the sources:
```
git clone https://github.com/pgul/udp-link.git
cd udp-link
make
sudo make install
```

You should install udp-link on both client and server side. If you have no root permission, it's possible to install it in you home directory. It's not needed to run it as a service.

It uses UDP port numbers 43200-44000 by default on server side (can be changed with --bind option), so you should open this port range in your firewall. Also check your ClientAlive* and TCPKeepAlive options in sshd_config on server side. In case of use udp-link it's better to unset them, otherwise server can close connection if it will not receive any packets from client during a minute or so.

## Architecture

When the program is started, in creates ssh connection to the target host (or to the jump server), generates random connection key, starts the program on the server side, creates udp link protected with this session key and then close ssh connection.

Similar applications are [mosh](https://github.com/mobile-shell/mosh), [Eternal Terminal](https://github.com/MisterTea/EternalTerminal) and quicssh.  
mosh is good, but it emulates terminal and it is not always convenient, for example, it has some problems with scroll-back buffer.
Eternal Terminal also emulates terminal, works over tcp and is not stable in my case (which is confirmed by open bugreports about crashes after network down and on multiple connections to the same remote host).  
QUIC protocol was developed exactly for this purpose, but implementations [quicssh](https://github.com/moul/quicssh) (go) and [quicssh-rs](https://github.com/oowl/quicssh-rs) (rust) are not stable on my tests.  
I did not found any program for this which satisfied me, but I spend much time in ssh, often with unstable or changing network, so I decided to create my own ssh proxy for make my ssh connections reliable and my life better. :)  
May be I'll change UDP-layer to [msquic library](https://github.com/microsoft/msquic) if found enough reasons for this.

In difference from mosh and Eternal Terminal, this program does not encrypt traffic. It is intended to be used with ssh, which encrypts traffic itself, and double encryption is not needed. It just change tcp transport layer to udp with increased reliability. Randomly choosed session key is used to protect udp link from unauthorized intrusions.

Tested on Linux (Ubuntu 22.04, amd64 and arm64) and MacOS.

## License

© 2023-2024 [Pavlo Gulchuk](https://gul.kiev.ua)
[MIT License](https://github.com/pgul/udp-link/blob/main/LICENSE)
