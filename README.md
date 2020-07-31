
# Note

Dns2tcp is a tool for TCP port forwarding over DNS. There is only
a simple identification mecanism but no encryption : DNS encapsulation
must be considered as an unsecure and anonymous transport
layer. It works similar to plink -L/-R options.
It is based on old version of dns2tcp at https://github.com/alex-sector/dns2tcp
with addition of port forwarding feature, bug fix and moving from b64 to b32.

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


## Examples


### Client:


Local port forwarding, for example to run meterpreter over DNS tunnel.
Listens to port 4444 on client side and forwards all connections to x.x.x.x:443 :
```sh
	$ dns2tcpc.exe -z mydomain.com -k secretkey -t 3 -L 4444:x.x.x.x:443 <dns_server>
	listening on port 4444
	...
	
```


Remote port forwarding, for example to make client SMB shares available to remote side.
Opens port 1500 for listening on server side and forwards all connections from remote to 127.0.0.1:445 :
```sh
        $ dns2tcpc.exe -z mydomain.com -k secretkey -t 3 -R 1500:127.0.0.1:445 <dns_server>
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

dns2tcpd server not supported on Windows

