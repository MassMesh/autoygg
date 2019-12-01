package main

import (
  "bytes"
  "encoding/json"
  "errors"
  "fmt"
  flag "github.com/spf13/pflag"
  //"github.com/brotherpowers/ipsubnet"
  "github.com/massmesh/autoygg/internal"
  "github.com/spf13/viper"
  "io/ioutil"
  "net/http"
  "os"
)

func logFatal(err error) {
  fmt.Printf("\nError: %s\n\n", err.Error())
  os.Exit(1)
}

func doPostRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string) (response []byte) {
  validActions := map[string]bool{
    "register": true,
    "renew": true,
    "release": true,
  }
  if ! validActions[action] {
    usage(fs)
    logFatal(errors.New("Invalid action: " + action))
  }
  var registration internal.Registration
  var err error
  err, registration.PublicKey = internal.GetSelfPublicKey()
  if err != nil {
    logFatal(err)
  }
  req, err := json.Marshal(registration)
  if err != nil {
    logFatal(err)
  }

  resp, err := http.Post("http://[" + gatewayHost + "]:" + gatewayPort + "/" + action, "application/json", bytes.NewBuffer(req))
  if err != nil {
    usage(fs)
    logFatal(err)
  }
  defer resp.Body.Close()

  response, err = ioutil.ReadAll(resp.Body)
  if err != nil {
    logFatal(err)
  }

  return
}

func setupRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  err = internal.EnableTunnelRouting()
  if err != nil {
    return
  }

  err = internal.AddLocalSubnet("0.0.0.0/0")
  if err != nil {
    fmt.Printf("%s\n", err)
  }

  internal.AddTunnelIP(clientIP,clientNetMask)

  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayAddRemoteSubnetCommand", "/usr/bin/yggdrasilctl addremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  //sub := ipsubnet.SubnetCalculator(clientIP, clientNetMask)
  //err := internal.AddRemoteSubnet(sub.GetNetworkPortion() + "/" + strconv.Itoa(clientNetMask), publicKey)
  err = internal.AddRemoteSubnet("0.0.0.0/0", publicKey)
  if err != nil {
    fmt.Printf("%s\n", err)
  }

  // Make sure we route traffic to our Yggdrasil peer(s) to the wan default gateway
  peers, err := internal.YggdrasilPeers()
  if err != nil {
    fmt.Printf("%s\n", err)
  }
  for _, p := range peers {
    // ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
    err = internal.AddPeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    if err != nil {
      fmt.Printf("%s\n", err)
    }
  }

  // Now change the default gateway
  internal.AddDefaultGateway(clientGateway)

  // FIXME TODO:
  // * discover wan_gw and wan_dev if not specified via cli, and do the ip ro add thing
  // * replace default route, test connectivity, if fail, rollback?
  return
}

func tearDownRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayRemoveRemoteSubnetCommand", "/usr/bin/yggdrasilctl removeremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  // Change the default gateway
  internal.RemoveDefaultGateway(clientGateway)

  // Undo the special Yggdrasil peer routes
  peers, err := internal.YggdrasilPeers()
  if err != nil {
    fmt.Printf("%s\n", err)
  }
  for _, p := range peers {
    // ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
    err = internal.RemovePeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    if err != nil {
      fmt.Printf("%s\n", err)
    }
  }

  err = internal.RemoveRemoteSubnet("0.0.0.0/0", publicKey)
  if err != nil {
    fmt.Printf("%s\n", err)
  }

  internal.RemoveTunnelIP(clientIP,clientNetMask)

  err = internal.RemoveLocalSubnet("0.0.0.0/0")
  if err != nil {
    fmt.Printf("%s\n", err)
  }

  err = internal.DisableTunnelRouting()
  if err != nil {
    return
  }

  return
}

func main() {
  var gatewayHost string
  var gatewayPort string
  var defaultGatewayIP string
  var defaultGatewayDevice string
  var action string

  fs := flag.NewFlagSet("Autoygg", flag.ContinueOnError)
  fs.Usage = func() { usage(fs) }

  fs.StringVar(&gatewayHost, "gateway-host", "", "Yggdrasil IP address of the gateway host")
  fs.StringVar(&gatewayPort, "gateway-port", "8080", "port of the gateway daemon")
  fs.StringVar(&defaultGatewayIP, "wan-gw-ip", "", "LAN default gateway IP address (e.g. 192.168.1.1)")
  fs.StringVar(&defaultGatewayDevice, "wan-gw-dev", "eth0", "LAN default gateway device")
  fs.StringVar(&action, "action", "register", "action (register/renew/release)")

  err := fs.Parse(os.Args[1:])
  if err != nil {
    logFatal(err)
  }

  if gatewayHost == "" || action == "" {
    usage(fs)
    os.Exit(1)
  }

  response := doPostRequest(fs,action,gatewayHost, gatewayPort)
  fmt.Println(string(response))
  var r internal.Registration
  err = json.Unmarshal(response, &r)
  if err != nil {
    logFatal(err)
  }
  if r.Error == "" {
    if action == "release" {
      err = tearDownRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, defaultGatewayIP, defaultGatewayDevice)
    } else {
      err = setupRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, defaultGatewayIP, defaultGatewayDevice)
    }
    if err != nil {
      logFatal(fmt.Errorf("%s",err))
    }
  } else {
    logFatal(fmt.Errorf("%s",r.Error))
  }
}
