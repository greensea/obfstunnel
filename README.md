obfstunnel
==========

Customizable network traffic tunneling tool


With obfstunnel, you can forward your traffic through firewall.
Currently we have _xor_ and _random_ obfs method. 

obfstunnel works both on client and server. When a user likes to connect
to another server outside a firewall, he could run obfstunnel in CLIENT
mode on his own machine, and run obfstunnel in SERVER mode on another
machine outside firewall. User should set up a target host he wants
connect to on SERVER side. After doing this, you can connect to
localhost, where obfstunnel listen on specified port. Once user
connected to localhost, obfstunnel will encode traffic and send to
obfstunnel on SERVER side. On SERVER side, obfstunnel will connect to
target host which user wants to, and forward user traffic.

<pre>
                             firewall
[user] <----> [obfstunnel] <---||---> [obfstunnel] <----> [target host]
       direct                do_obfs               direct
</pre>



## Example ##

### Tunneling SSH through firewall ###

We are in machine A, and wants to SSH to server B, but we can not direct
connect to server B via SSH because a firewall is block SSH connection.
obfstunnel can help us.

We will use obfstunnel builtin obfs method, the random method. The
random method could make traffic like random traffic, so firewall could
not detect SSH connection and could not block it.

On server side, or server B, we run obfstunnel like this:

    obfstunnel -s 2000 -t localhost:22 -m xor

__-s 2000__ argument cause obfstunnel runs in SERVER mode and listen on
port 2000 waiting for client connection.

__-t localhost:22__ tell obfstunnel forward traffic to localhost, where
SSH service run on port 22.

__-m xor__ tell obfstunnel to use xor obfs method.

On client side, or machine A, run obfstunnel like this:

    obfstunnel -c 22 -t 1.1.1.1:2000 -m xor

__-c 22__ cause obfstunnel runs in CLIENT mode, waiting user connection
on port 22.

__-t 1.1.1.1:2000__ tells obfstunnel where server is located. 1.1.1.1 is
IP address of server A, 2000 is the port obfstunnel in SERVER mode
listen on.

Now run _ssh localhost_ , you will find you are connecting to server B.

