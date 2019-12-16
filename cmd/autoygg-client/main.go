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
  "log"
  "io/ioutil"
  "net/http"
  "os"
)

var debug bool

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
  log.Printf("Enabling Yggdrasil tunnel routing")
  err = internal.EnableTunnelRouting()
  handleError(err)
  if err != nil {
    return
  }

  log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
  err = internal.AddLocalSubnet("0.0.0.0/0")
  handleError(err)

  log.Printf("Adding tunnel IP %s/%d",clientIP,clientNetMask)
  err = internal.AddTunnelIP(clientIP,clientNetMask)
  handleError(err)

  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayAddRemoteSubnetCommand", "/usr/bin/yggdrasilctl addremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  log.Printf("Adding Yggdrasil remote subnet 0.0.0.0/0")
  err = internal.AddRemoteSubnet("0.0.0.0/0", publicKey)
  handleError(err)

  // Make sure we route traffic to our Yggdrasil peer(s) to the wan default gateway
  log.Printf("Getting Yggdrasil peers")
  peers, err := internal.YggdrasilPeers()
  handleError(err)

  for _, p := range peers {
    // ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
    log.Printf("Adding Yggdrasil peer route for %s via %s",p,defaultGatewayIP)
    err = internal.AddPeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    handleError(err)
    if err != nil {
      // If we can't add a route for all yggdrasil peers, something is really wrong and we should abort.
      // Because if we change the default gateway, we will be cutting ourselves off from the internet.
      return
    }
  }

  log.Printf("Adding default gateway pointing at %s",clientGateway)
  err = internal.AddDefaultGateway(clientGateway)
  handleError(err)

  // FIXME TODO:
  // * discover wan_gw and wan_dev if not specified via cli, and do the ip ro add thing
  // * replace default route, test connectivity, if fail, rollback?
  return
}

func handleError(err error) {
  if err != nil {
    if !internal.Quiet {
      fmt.Printf("[ FAIL ]\n")
    }
    fmt.Printf("-> %s\n", err)
  } else {
    if !internal.Quiet {
      fmt.Printf("[ ok ]\n")
    }
  }
}

func tearDownRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  // FIXME do we want to make this properly configurable?
  viper.SetDefault("GatewayRemoveRemoteSubnetCommand", "/usr/bin/yggdrasilctl removeremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")

  log.Printf("Removing default gateway pointing at %s",clientGateway)
  err = internal.RemoveDefaultGateway(clientGateway)
  handleError(err)

  log.Printf("Getting Yggdrasil peers")
  peers, err := internal.YggdrasilPeers()
  handleError(err)

  for _, p := range peers {
    log.Printf("Removing Yggdrasil peer route for %s via %s",p,defaultGatewayIP)
    err = internal.RemovePeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
    handleError(err)
  }

  log.Printf("Removing Yggdrasil remote subnet 0.0.0.0/0")
  err = internal.RemoveRemoteSubnet("0.0.0.0/0", publicKey)
  handleError(err)

  log.Printf("Removing tunnel IP %s/%d",clientIP,clientNetMask)
  err = internal.RemoveTunnelIP(clientIP,clientNetMask)
  handleError(err)

  log.Printf("Removing Yggdrasil local subnet 0.0.0.0/0")
  err = internal.RemoveLocalSubnet("0.0.0.0/0")
  handleError(err)

  log.Printf("Disabling Yggdrasil tunnel routing")
  err = internal.DisableTunnelRouting()
  handleError(err)

  return
}

func main() {
  // Initialize our own LogWriter that right justifies all lines at 70 characters
  // and removes the trailing newline from log statements. Used for status lines
  // where we want to write something, then execute a command, and follow with
  // [ok] or [FAIL] on the same line.
  log.SetFlags(0)
  log.SetOutput(new(internal.LogWriter))

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
  fs.BoolVar(&debug, "debug", false, "debug output")
  fs.BoolVar(&internal.Quiet, "quiet", false, "suppress non-error output")

  err := fs.Parse(os.Args[1:])
  if err != nil {
    logFatal(err)
  }

  if gatewayHost == "" || action == "" {
    usage(fs)
    os.Exit(1)
  }

  response := doPostRequest(fs,action,gatewayHost, gatewayPort)
  if debug {
    fmt.Printf("Raw server response:\n\n%s\n\n",string(response))
  }
  var r internal.Registration
  err = json.Unmarshal(response, &r)
  if err != nil {
    if action == "release" {
      // Do not abort when we are trying to release a lease, continue with the tearDownRoutes below
      fmt.Println(err)
    } else {
      logFatal(err)
    }
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
