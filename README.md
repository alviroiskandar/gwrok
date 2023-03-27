# Author
- Alviro Iskandar Setiawan (57741034)

# gwrok
A simple TCP port forwarder for GNU/Weeb. Inspired by [ngrok](https://ngrok.com/).

![gwrok visualization](gwrok.drawio.svg?raw=true "gwrok visualization")

# Dependencies
  - make (build only)
  - gcc (build only)
  - libc


# How to build gwrok?
```
sudo apt-get install make gcc -y;
make;
```

## gwrok client
```
viro@freezing-night:~/p/gwrok$ ./gwrok client --help

Usage: ./gwrok client [options]

Options:

  -H, --help			Show this help
  -s, --server-addr=<addr>	Server address (default: 188.166.250.196)
  -P, --server-port=<port>	Server port (default: 8000)
  -t, --target-addr=<addr>	Target address (required)
  -p, --target-port=<port>	Target port (required)
  -m, --max-clients=<num>	Max clients (default: 128)
  -v, --verbose			Verbose mode

```

## gwrok server
```
viro@freezing-night:~/p/gwrok$ ./gwrok server --help

Usage: ./gwrok server [options]

Options:

  -H, --help			Show this help
  -h, --bind-addr=<addr>	Bind address (default: 188.166.250.196)
  -p, --bind-port=<port>	Bind port (default: 8000)
  -s, --shared-addr=<addr>	Shared address (required)
  -m, --max-clients=<num>	Max clients (default: 128)
  -v, --verbose			Verbose mode

```

# Server usage example
Let's say you want to share your VPS public IP address (188.166.250.196) using
the gwrok server. You can do:
```
./gwrok server --shared-addr 188.166.250.196 --bind-addr 0.0.0.0 -p 8000
```
Make sure you have opened port 8000 and all ports for the shared address in your
firewall.


# Client usage example
For example, if you have a web server running on your local machine with address
127.0.0.1 and port 80. You want to make it accessible from the internet. You can
use gwrok to do that:
```
./gwrok client --target-addr 127.0.0.1 --target-port 80
```
By default it will use my server 188.166.250.196:8000. It will not last forever
though. You can also use your own gwrok server by specifying the server address
and port with `--server-addr` and `--server-port` options like:
```
./gwrok client --target-addr 127.0.0.1 --target-port 80 --server-addr 123.123.123.123 --server-port 8000
```
where 123.123.123.123 is your server address and 8000 is the port you have
opened for gwrok server.


tq

-- Viro


# Screenshots
![gwrok on Ubuntu 001](ss_001.png?raw=true "gwrok on Ubuntu 001")
![gwrok on Ubuntu 002](ss_002.png?raw=true "gwrok on Ubuntu 002")
![gwrok on Android 001](ss_android_001.jpg?raw=true "gwrok on Android 001")
![gwrok on Android 002](ss_android_002.jpg?raw=true "gwrok on Android 002")

# License
GNU General Public License v2.0
