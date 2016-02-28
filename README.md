# icmptun
School project for Networking course. I'm releasing it under MIT licence, you can do whatever you want with it. 

It's rather concept than complete and fully tested piece of software. It can be particularly usefull for learning way how to use TUN module to create tunnel devices and how to use libnetfilter_queue.

This programs create linux tunnel network interface (using TUN kernel module). Everything you send into this interface is encapsulated with ICMP echo packet headers and send to other side. Using this, you can create IP tunnel between two sides in Internet and on the network you can only see that these sides are exchanging ICMP ping (echo) request and responses. ICMP echo request/replies can be of variable length, it can contain optional payload. This place for payload is used as a place where to hide original packets (for more safety, it also encrypt original packet by [salsa20](https://en.wikipedia.org/wiki/Salsa20) cipher).

## Compiling and using

You need libssl-dev, libnetfilter-queue-dev and libnetfilter-queue1 to be able to compile this programs. These names of packages is valid for Debian, it can be named differently in other distributions.

Before using, you must have kernel module tun loaded (modprobe tun). Programs can run in server or client mode (after make you should get icmptun_client and icmptun_server programs). In client mode, you have to specify IP of server. You don't need to specify that for server, server automatically learns IPs of clients. For both modes must also specify encryption key (its used for encrypting original packets). You can use any strings as encryption keys, SHA256 is then used for creating real encryption keys. 

After starting program, it creates network interface. To use it, you should assing link adresses to that interface (on both client and server) and then you can use it (you can route throught it, for example you can change default gateway to adress of the other side of the tunnel).