# gwrok
A simple TCP port forwarder for GNU/Weeb. Inspired by [ngrok](https://ngrok.com/).


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


# Client usage example
For example, if you have a web server running on your local machine with address
127.0.0.1 and port 80. You want to make it accessible from the internet. You can
use gwrok to do that:
```
./gwrok client --target-addr 127.0.0.1 --target-port 80
```
By default it will use my server 188.166.250.196:8000. It will not last forever
though. You can also use your own gwrok server by specifying the server address
and port with `--server-addr` and `--server-port` options.

tq

-- Viro


# License
GNU General Public License v2.0


# Author
Alviro Iskandar Setiawan &lt;alviro.iskandar@gnuweeb.org&gt;
