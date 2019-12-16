
Autoygg is a tool to automatically configure an internet egress node on an
[yggdrasil](https://yggdrasil-network.github.io/) network.

There is a server component (autoygg-server) which acts as egress gatekeeyper
on an yggdrasil node with internet access (e.g. a VPS in the cloud). It has a
REST api that is consumed by the client component (autoygg-client).

The client can register with the server for internet egress access. When it
gets a successful response from the server, it will configure the local
yggdrasil node to send all internet-bound traffic out via the node that runs
autoygg-server. Because the traffic between the client and server runs over the
yggdrasil network, it is end-to-end encrypted until the point of egress to the
internet.

## Building the software

GNU Make and a Go compiler, version 1.11 or higher are required.

Build the software with the *make* command. The resulting binaries will be in the

```
cmd/autoygg-client/
cmd/autoygg-server/
```

directories.

## Quick start

Example session:

1) On the machine that will run *autoygg-server*, create a config file at /etc/autoygg/config.yaml, e.g. with these contents:

```
---
ListenHost: "the:yggdrasil:ip:address:of:this:machine"
AllowRegistration: true
GatewayTunnelIP: "10.42.0.1"
GatewayTunnelNetmask: "16"
```

Get the value for 'ListenHost' by running

```
yggdrasilctl getSelf
```

2) run autoygg-server, e.g. in screen:

```
./autoygg-server
```

3) Now switch to machine that will run *autoygg-client*. Because the client will reconfigure your local networking, it needs sufficient privileges to do so, e.g. by using sudo to invoke it.

Supply the yggdrasil IP of the node that runs autoygg-server as *--gateway-host*. You do not need to be peered directly with that node. The *--wan-gw-dev* and *--wan-gw-ip* values are your current local default gateway information. It is needed by the *autoygg-client* tool because a host route to your local gateway IP needs to be installed for each of your Yggdrasil peers! The default values for the default gateway device and address are respectively eth0 and 192.168.1.1, and they may be omitted if your values match those defaults.

```
$ sudo ./autoygg-client --gateway-host the:yggdrasil:ip:where:autoygg-server:runs --wan-gw-dev eth0 --wan-gw-ip 192.168.10.1 --action register
Enabling Yggdrasil tunnel routing                                     [ ok ]
Adding Yggdrasil local subnet 0.0.0.0/0                               [ ok ]
Adding tunnel IP 10.42.42.1/16                                        [ ok ]
Adding Yggdrasil remote subnet 0.0.0.0/0                              [ ok ]
Getting Yggdrasil peers                                               [ ok ]
Adding Yggdrasil peer route for X.X.X.X via 192.168.10.1              [ ok ]
Adding default gateway pointing at 10.42.0.1                          [ ok ]
```

Tearing the session back down again will return your network configuration to its previous state:

```
sudo ./autoygg-client --gateway-host the:yggdrasil:ip:where:autoygg-server:runs --wan-gw-dev eth0 --wan-gw-ip 192.168.10.1 --action release
Removing default gateway pointing at 10.42.0.1                        [ ok ]
Getting Yggdrasil peers                                               [ ok ]
Removing Yggdrasil peer route for X.X.X.X via 192.168.13.1            [ ok ]
Removing Yggdrasil remote subnet 0.0.0.0/0                            [ ok ]
Removing tunnel IP 10.42.42.1/16                                      [ ok ]
Removing Yggdrasil local subnet 0.0.0.0/0                             [ ok ]
Disabling Yggdrasil tunnel routing                                    [ ok ]
```

## Hacking

GNU Make and a Go compiler, version 1.11 or higher are required. In addition,
[GolangCI-Lint](https://github.com/golangci/golangci-lint) is needed.

Build the software with the *make dev* command.

## Licensing

Autoygg is Free Software, released under the GNU Affero GPL v3 or later. See the LICENSE file for the text of the license.
