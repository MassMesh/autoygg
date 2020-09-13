
# autoygg-server

## Description

`autoygg-server` is an internet egress gatekeeper. It runs on an Yggdrasil node with internet (and/or VPN) access. It has a REST api that is consumed by `autoygg-client` for requesting access. The REST api endpoint is the Yggdrasil IP of the machine that runs `autoygg-server`, by default on port 8080. All traffic between the clients and `autoygg-server` happens via the Yggdrasil network.

On startup, `autoygg-server` sets up some rudimentary firewall rules, enables IP forwarding, enables Yggdrasil tunnel routing and adds an Yggdrasil local subnet. It then sets up an `ip rule` to send all traffic from the clients via a dedicated routing table, and finally sets the tunnel IP and netmask on the configured Yggdrasil interface. On shutdown, `autoygg-server` does its best to undo all those changes.

When an `autoygg-client` registers for internet access, `autoygg-server` uses its operating mode (see [the specification](SPEC.md)) to determine if access should be granted. If so, it issues an IP address to the client from its configured range. It then instructs Yggdrasil to add a remote subnet for the client, at which point the client can route internet traffic through the gateway. Each client lease has an expiry time, and the client is expected to renew its lease before the lease period expires.

## Requirements

`autoygg-server` must be run as root.

`autoygg-server` requires a running Yggdrasil daemon.

In its default configuration, `autoygg-server` requires the `yggdrasilctl`, `ip` and `iptables` commands in its PATH.

## Configuration

### Systemd unit file

`autoygg-server` ships with a [systemd unit file](../systemd/autoygg-server.service).

### File locations

By default, `autoygg-server` will accept parameters in two configuration files named *server.yaml* and *accesslist.yaml*, which can be located in */etc/autoygg/* or in the directory the *autoygg-server* binary is executed from. **`autoygg-server` will automatically reload its config files when they change**. With the exception of changes that affect the commands issued at startup, there is no need to restart `autoygg-server` after modifying its config file or accesslist. A few parameters may be specified as command line arguments. The complete list of parameters can be consulted by running *autoygg-server --help*, e.g.:

```
$ ./autoygg-server --help

autoygg-server provides internet egress for Yggdrasil nodes running autoygg-client.

Options:
      --dumpConfig   dump the configuration that would be used by autoygg-server and exit
      --help         print usage and exit
```

`autoygg-server` has a number of configuration options. To see the current configuration, use

  ```
  autoygg-server --dumpConfig
  ```

All the commands used to configure firewall rules, ip rules, ip routes, and yggdrasil are configurable.

### Example

See the [quick start](../README.md#quick-start) for a configuration example.

## VPN egress

`autoygg-server` has support for sending mesh traffic out via a VPN.

OpenVPN example: configure OpenVPN with these directives:

  ```
  dev vpn0
  dev-type tun
  route-nopull
  ```

Then, to configure VPN egress in `autoygg-server`, set the `GatewayWanInterface` configuration option to the VPN interface `vpn0`. This will cause `autoygg-server` to add a default route via that interface to the mesh routing table (update the `RoutingTableNumber` config option to change the routing table ID). The `GatewayWanInterface` is also used in the firewall rules that `autoygg-server` sets up.

To avoid future routing table namespace conflicts, it is recommended to add the `RoutingTableNumber` ID to the `/etc/iproute2/rt_tables` file. This is optional, e.g.:

  ```
  42      mesh
  ```

Finally, restart OpenVPN and `autoygg-server`. Please note: `autoygg-server` can only start up when the `vpn0` interface exists.

## Database

`autoygg-server` stores client and lease state in a SQLite database. By default that database is stored at

  ```
  /var/lib/autoygg/autoygg.db
  ```

The directory can be changed with the `StateDir` configuration setting.

## Restarting and downtime

Because `autoygg-server` is not in the data path between its clients and the internet, it is relatively safe to restart `autoygg-server`. Existing clients with a lease will not be affected. During the restart, the REST api will not be available. Clients trying to reach the REST api will retry their requests automatically. In other words, only clients with an expired or no lease, trying to create a new lease, will experience downtime while the `autoygg-server` REST api is not available.
