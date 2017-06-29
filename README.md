# tcp_killer

Shuts down a TCP connection on Linux or macOS. Local and remote endpoint arguments can be copied from the output of 'netstat -lanW'.

The functionality offered by *tcp_killer* is intended to mimic [TCPView](https://technet.microsoft.com/en-us/sysinternals/tcpview.aspx)'s "Close Connection" functionality on Linux and macOS.

## Basic Usage

`python tcp_killer.py [-verbose] <local endpoint> <remote endpoint>`

Arguments:

    -verbose           Show verbose output
    <local endpoint>   Connection's local IP address and port
    <remote endpoint>  Connection's remote IP address and port

Examples:

    tcp_killer.py 10.31.33.7:50246 93.184.216.34:443
    tcp_killer.py 2001:db8:85a3::8a2e:370:7334.93 2606:2800:220:1:248:1893:25c8:1946.80
    tcp_killer.py -verbose [2001:4860:4860::8888]:46820 [2607:f8b0:4005:807::200e]:80

## Full Example
```
geffner@ubuntu:~$ # Create a server to listen on TCP port 12345
geffner@ubuntu:~$ nc -d -l -p 12345 &
[1] 135578

geffner@ubuntu:~$ # Connect to the local server on TCP port 12345
geffner@ubuntu:~$ nc -v -d localhost 12345 &
[2] 135579
Connection to localhost 12345 port [tcp/*] succeeded!

geffner@ubuntu:~$ # Find the connection endpoints
geffner@ubuntu:~$ netstat -lanW | grep 12345.*ESTABLISHED
tcp        0      0 127.0.0.1:33994         127.0.0.1:12345         ESTABLISHED
tcp        0      0 127.0.0.1:12345         127.0.0.1:33994         ESTABLISHED

geffner@ubuntu:~$ # Kill the connection by copying and pasting the output of netstat
geffner@ubuntu:~$ python tcp_killer.py 127.0.0.1:33994         127.0.0.1:12345
TCP connection was successfully shutdown.
[1]-  Done                    nc -d -l -p 12345
[2]+  Done                    nc -v -d localhost 12345
```

## Dependencies
This program uses the [frida](https://www.frida.re/) framework to perform code injection.

Frida can be installed as follows: `sudo pip install frida`

## Disclaimer

This is not an official Google product.