# gwrok
A simple TCP port forwarder for GNU/Weeb. Inspired by [ngrok](https://ngrok.com/).

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

# License
GNU General Public License v2.0

# Author
Alviro Iskandar Setiawan &lt;alviro.iskandar@gnuweeb.org&gt;
