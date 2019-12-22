package internal

import (
  "bytes"
  "encoding/json"
  "fmt"
  flag "github.com/spf13/pflag"
  //"github.com/brotherpowers/ipsubnet"
  "github.com/spf13/viper"
  "log"
  "io/ioutil"
  "net/http"
  "os"
)

func ClientUsage(fs *flag.FlagSet) {
  fmt.Fprintf(os.Stderr, `
autoygg-client is a tool to register an Yggdrasil node with a gateway for internet egress.

Options:
`)
  fs.PrintDefaults()
}

func DoPostRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string) (response []byte) {
  validActions := map[string]bool{
    "register": true,
    "renew": true,
    "release": true,
  }
  if ! validActions[action] {
    ClientUsage(fs)
    Fatal("Invalid action: " + action)
  }
  var registration Registration
  var err error
  err, registration.PublicKey = GetSelfPublicKey()
  if err != nil {
    Fatal(err)
  }
  req, err := json.Marshal(registration)
  if err != nil {
    Fatal(err)
  }

  resp, err := http.Post("http://[" + gatewayHost + "]:" + gatewayPort + "/" + action, "application/json", bytes.NewBuffer(req))
  if err != nil {
    ClientUsage(fs)
    Fatal(err)
  }
  defer resp.Body.Close()

  response, err = ioutil.ReadAll(resp.Body)
  if err != nil {
    Fatal(err)
  }

  return
}

func ClientSetupRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  log.Printf("Enabling Yggdrasil tunnel routing")
  err = EnableTunnelRouting()
  HandleError(err,false)
  if err != nil {
    return
  }

  log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
  err = AddLocalSubnet("0.0.0.0/0")
  HandleError(err,false)

  log.Printf("Adding tunnel IP %s/%d",clientIP,clientNetMask)
  err = AddTunnelIP(clientIP,clientNetMask)
  HandleError(err,false)

  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayAddRemoteSubnetCommand", "/usr/bin/yggdrasilctl addremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  log.Printf("Adding Yggdrasil remote subnet 0.0.0.0/0")
  err = AddRemoteSubnet("0.0.0.0/0", publicKey)
  HandleError(err,false)

  // Make sure we route traffic to our Yggdrasil peer(s) to the wan default gateway
  log.Printf("Getting Yggdrasil peers")
  peers, err := YggdrasilPeers()
  HandleError(err,false)

  for _, p := range peers {
    // ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
    log.Printf("Adding Yggdrasil peer route for %s via %s",p,defaultGatewayIP)
    err = AddPeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    HandleError(err,false)
    if err != nil {
      // If we can't add a route for all yggdrasil peers, something is really wrong and we should abort.
      // Because if we change the default gateway, we will be cutting ourselves off from the internet.
      return
    }
  }

  log.Printf("Adding default gateway pointing at %s",clientGateway)
  err = AddDefaultGateway(clientGateway)
  HandleError(err,false)

  // FIXME TODO:
  // * discover wan_gw and wan_dev if not specified via cli, and do the ip ro add thing
  // * replace default route, test connectivity, if fail, rollback?
  return
}

func ClientTearDownRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayRemoveRemoteSubnetCommand", "/usr/bin/yggdrasilctl removeremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  log.Printf("Removing default gateway pointing at %s",clientGateway)
  err = RemoveDefaultGateway(clientGateway)
  HandleError(err,false)

  log.Printf("Getting Yggdrasil peers")
  peers, err := YggdrasilPeers()
  HandleError(err,false)

  for _, p := range peers {
    log.Printf("Removing Yggdrasil peer route for %s via %s",p,defaultGatewayIP)
    err = RemovePeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    HandleError(err,false)
  }

  log.Printf("Removing Yggdrasil remote subnet 0.0.0.0/0")
  err = RemoveRemoteSubnet("0.0.0.0/0", publicKey)
  HandleError(err,false)

  log.Printf("Removing tunnel IP %s/%d",clientIP,clientNetMask)
  err = RemoveTunnelIP(clientIP,clientNetMask)
  HandleError(err,false)

  log.Printf("Removing Yggdrasil local subnet 0.0.0.0/0")
  err = RemoveLocalSubnet("0.0.0.0/0")
  HandleError(err,false)

  log.Printf("Disabling Yggdrasil tunnel routing")
  err = DisableTunnelRouting()
  HandleError(err,false)

  return
}

func ClientMain() {
  SetupLogWriter()

  var gatewayHost string
  var gatewayPort string
  var defaultGatewayIP string
  var defaultGatewayDevice string
  var action string

  fs := flag.NewFlagSet("Autoygg", flag.ContinueOnError)
  fs.Usage = func() { ClientUsage(fs) }

  fs.StringVar(&gatewayHost, "gateway-host", "", "Yggdrasil IP address of the gateway host")
  fs.StringVar(&gatewayPort, "gateway-port", "8080", "port of the gateway daemon")
  fs.StringVar(&defaultGatewayIP, "wan-gw-ip", "", "LAN default gateway IP address (e.g. 192.168.1.1)")
  fs.StringVar(&defaultGatewayDevice, "wan-gw-dev", "eth0", "LAN default gateway device")
  fs.StringVar(&action, "action", "register", "action (register/renew/release)")
  fs.BoolVar(&Debug, "debug", false, "debug output")
  fs.BoolVar(&Quiet, "quiet", false, "suppress non-error output")

  err := fs.Parse(os.Args[1:])
  if err != nil {
    Fatal(err)
  }

  if gatewayHost == "" || action == "" {
    ClientUsage(fs)
    os.Exit(1)
  }

  response := DoPostRequest(fs,action,gatewayHost, gatewayPort)
  if Debug {
    fmt.Printf("Raw server response:\n\n%s\n\n",string(response))
  }
  var r Registration
  err = json.Unmarshal(response, &r)
  if err != nil {
    if action == "release" {
      // Do not abort when we are trying to release a lease, continue with the ClientTearDownRoutes below
      fmt.Println(err)
    } else {
      Fatal(err)
    }
  }
  if r.Error == "" {
    if action == "release" {
      err = ClientTearDownRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, defaultGatewayIP, defaultGatewayDevice)
    } else {
      err = ClientSetupRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, defaultGatewayIP, defaultGatewayDevice)
    }
    if err != nil {
      Fatal(err)
    }
  } else {
    Fatal(r.Error)
  }
}
