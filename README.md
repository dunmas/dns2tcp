
# Note

The source repository https://github.com/kirillwow/dns2tcp has a problem with processing the `server` parameter (it is missing) and compiling on modern systems (tested on `Ubuntu 22.04`).

These errors have been fixed here, which allows you to run the tool in local networks with arbitrary DNS servers for access.

The corrections were made at the cost of possible problems with displaying some error messages.

## How to build

### Linux

	$ ./configure
	$ make
	$ ./server/dns2tcpd
	$ ./client/dns2tcpc


### Windows

	$ cd dns2tcp/client
	$ "C:\Program Files\mingw-w64\x86_64-8.1.0-win32-seh-rt_v6-rev0\mingw64\bin\gcc.exe" -I ..\common\includes -I includes *.c ..\common\*.c -l ws2_32 -l iphlpapi -o dns2tcpc.exe
	$ dns2tcpc.exe

MinGW download link: https://github.com/rcpacini/mingw-w64/blob/master/MinGW-W64%20GCC-8.1.0/x86_64-8.1.0-release-win32-seh-rt_v6-rev0.7z

## Examples


### Client:


Local port forwarding, for example to run meterpreter over DNS tunnel.
Listens to port 4444 on client side and forwards all connections to x.x.x.x:443 :
```sh
	$ dns2tcpc.exe -z mydomain.com -k secretkey -t 3 -L 4444:x.x.x.x:443 -S <dns_server>
	listening on port 4444
	...
	
```


Remote port forwarding, for example to make client SMB shares available to remote side.
Opens port 1500 for listening on server side and forwards all connections from remote to 127.0.0.1:445 :
```sh
        $ dns2tcpc.exe -z mydomain.com -k secretkey -t 3 -R 1500:127.0.0.1:445 -S <dns_server>
        Connected to port : 445
        ...

```


File configuration :

### Server :

```sh
	# cat > .dns2tcpdrc << EOF
	
	listen = *server ip address*
	port = 53
	user = nobody
	key = secretkey
	chroot = /var/empty/dns2tcp/
	domain = mydomain.com

	EOF

	# server/dns2tcpd -F -d3 -f .dns2tcpdrc	

```

# Known Bugs

dns2tcpd server not supported on Windows (not a big problem for security testers btw)

