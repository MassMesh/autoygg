package internal

import (
  "fmt"
  "github.com/spf13/viper"
  "github.com/jinzhu/gorm"
  _ "github.com/jinzhu/gorm/dialects/sqlite"
  "log"
  "os"
  "os/exec"
  "regexp"
  "strconv"
  "strings"
  "time"
)

var Debug bool
var Quiet bool
var EnablePrometheus bool

type LogWriter struct {
}

func (writer LogWriter) Write(bytes []byte) (int, error) {
  if !Quiet {
    // Strip the last character, it's a newline!
    return fmt.Printf("%-70s",string(bytes[:len(bytes)-1]))
  } else {
    return 0, nil
  }
}

type Info struct {
    GatewayOwner  string
    Description   string
    RegistrationRequired bool
}

// State:
// pending: needs human approval
// open: ready for the yggdrasil goroutine to execute
// success: all set
// fail: yggdrasil goroutine reported failure
// removed: yggdrasil registration removed, pending deletion

type Registration struct {
  gorm.Model
  State             string
  GatewayPublicKey  string
  PublicKey         string
  YggIP             string  // The Yggdrasil IP address
  ClientIP          string  // The tunnel IP address assigned to the client
  ClientNetMask     int     // The tunnel netmask
  ClientGateway     string
  ClientInfo        string
  LeaseExpires      time.Time
  Error             string
}

// Fatal error. Do not call this from the server code after the
// initialization phase.
func Fatal(err interface{}) {
  // Reset the log settings to the default
  log.SetFlags(log.LstdFlags)
  log.SetOutput(os.Stderr)
  log.Fatal("Error: ", err)
}

func AddTunnelIP(IPAddress string, NetMask int) (err error) {
  return TunnelIPWorker("add", IPAddress, NetMask)
}

func RemoveTunnelIP(IPAddress string, NetMask int) (err error) {
  return TunnelIPWorker("del", IPAddress, NetMask)
}

func TunnelIPWorker(action string, IPAddress string, NetMask int) (err error) {
  out, err := exec.Command("ip","addr","list","tun0").Output()
  if err != nil {
    err = fmt.Errorf("Unable to run `ip addr list tun0`: %s", err)
    return
  }

  found := strings.Index(string(out),IPAddress + "/" + strconv.Itoa(NetMask))

  if (action == "add" && found == -1) || (action == "del" && found != -1) {
    _, err = exec.Command("ip","addr",action,IPAddress + "/" + strconv.Itoa(NetMask),"dev","tun0").Output()
    if err != nil {
      err = fmt.Errorf("Unable to run `ip addr %s %s/%d dev tun0`: %s", action, IPAddress, NetMask, err)
      return
    }
  }
  return
}

func AddRemoteSubnet(Subnet string, PublicKey string) (err error) {
  return RemoteSubnetWorker("Add", Subnet, PublicKey)
}

func RemoveRemoteSubnet(Subnet string, PublicKey string) (err error) {
  return RemoteSubnetWorker("Remove", Subnet, PublicKey)
}

func RemoteSubnetWorker(Action string, Subnet string, PublicKey string) (err error) {
  out, err := ExecuteYggdrasilCtl("getroutes")
  if err != nil {
    return
  }
  matched, err := regexp.Match(Subnet, out)
  if err != nil {
    return
  }
  if (matched && Action == "Add") || (!matched && Action == "Remove") {
    // We don't need to do anything
    return
  }

  command := viper.GetString("Gateway" + Action + "RemoteSubnetCommand")
  command = strings.Replace(command, "%%SUBNET%%", Subnet, -1)
  command = strings.Replace(command, "%%CLIENT_PUBLIC_KEY%%", PublicKey, -1)

  commandSlice := strings.Split(command," ")
  cmd := exec.Command(commandSlice[0],commandSlice[1:]...)
  err = cmd.Run()
  if err != nil {
    err = fmt.Errorf("Unable to run `%s`: %s", command, err)
  }

  return
}

// ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
func AddPeerRoute (peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  return PeerRouteWorker("add", peer, defaultGatewayIP, defaultGatewayDevice)
}

// ip ro del <peer_ip> via <wan_gw> dev <wan_dev>
func RemovePeerRoute (peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  return PeerRouteWorker("del", peer, defaultGatewayIP, defaultGatewayDevice)
}

func PeerRouteWorker (action string, peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
  cmdArgs := []string{"ro","list",peer,"via",defaultGatewayIP,"dev",defaultGatewayDevice}
  out, err := exec.Command("ip",cmdArgs...).Output()
  if err != nil {
    err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs," "), err)
    return
  }
  if (action == "add" && strings.TrimSpace(string(out)) == peer) || (action == "del" && len(out) == 1) {
    // Nothing to do!
    return
  }

  cmdArgs = []string{"ro",action,peer,"via",defaultGatewayIP,"dev",defaultGatewayDevice}
  _, err = exec.Command("ip",cmdArgs...).Output()
  if err != nil {
    err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs," "), err)
  }
  return
}

// ip ro add default via <ygg_gateway_ip>
func AddDefaultGateway(clientGateway string) (err error) {
  return DefaultGatewayWorker("add",clientGateway)
}

func RemoveDefaultGateway(clientGateway string) (err error) {
  return DefaultGatewayWorker("del",clientGateway)
}

func DefaultGatewayWorker(action string, clientGateway string) (err error) {
  cmdArgs := []string{"ro",action,"default","via",clientGateway}
  _, err = exec.Command("ip",cmdArgs...).Output()
  if err != nil {
    err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs," "), err)
  }
  return
}


//                                        bytes_recvd    bytes_sent    endpoint                                      port  proto  uptime
//200:40ff:e447:5bb6:13ee:8a9a:e71d:b6ee  817789         0             tcp://[fe80::109a:683d:a72:c4f5%wlan0]:45279  2     tcp    11:16:30
//201:44e1:28f0:af3c:cf1b:6e2a:79bd:44b0  14578499       14497520      tcp://50.236.201.218:56088                    3     tcp    11:15:45
func YggdrasilPeers() (peers []string, err error) {
  err, selfAddress := GetSelfAddress()

  out, err := ExecuteYggdrasilCtl("getPeers")
  if err != nil {
    return
  }
  var matched bool
  for _, l := range strings.Split(string(out), "\n") {
    matched, err = regexp.MatchString("^2", l)
    if err != nil {
      return
    }

    if !matched {
      // Not a line that starts with a peer address
      continue
    }
    if strings.HasPrefix(l,selfAddress) {
      // Skip ourselves
      continue
    }

    re := regexp.MustCompile(` .*?://(.*?):.* `)
    match := re.FindStringSubmatch(l)
    if len(match) < 1 {
      err = fmt.Errorf("Unable to parse yggdrasilctl output: %s",l)
      return
    }
    peers = append(peers, match[1])
  }
  return
}

func ExecuteYggdrasilCtl(cmd ...string) (out []byte, err error) {
  out, err = exec.Command("yggdrasilctl",cmd...).Output()
  if err != nil {
    err = fmt.Errorf("Unable to run `yggdrasilctl %s`: %s", strings.Join(cmd," "), err)
  }
  return
}

func EnableTunnelRouting() (err error) {
  return TunnelRoutingWorker("true")
}

func DisableTunnelRouting() (err error) {
  return TunnelRoutingWorker("false")
}

func TunnelRoutingWorker(State string) (err error) {
  out, err := ExecuteYggdrasilCtl("gettunnelrouting")
  if err != nil {
    return
  }

  var matched bool
  if State == "true" {
    matched, err = regexp.Match("Tunnel routing is enabled", out)
    if err != nil || matched {
      return
    }
  } else {
    matched, err = regexp.Match("Tunnel routing is disabled", out)
    if err != nil || matched {
      return
    }
  }

  _, err = ExecuteYggdrasilCtl("settunnelrouting", "enabled=" + State)
  if err != nil {
    return
  }

  return
}

func AddLocalSubnet(Subnet string) (err error) {
  return LocalSubnetWorker("add", Subnet)
}

func RemoveLocalSubnet(Subnet string) (err error) {
  return LocalSubnetWorker("remove", Subnet)
}

func LocalSubnetWorker(Action string, Subnet string) (err error) {
  out, err := ExecuteYggdrasilCtl("getsourcesubnets")
  if err != nil {
    return
  }

  matched, err := regexp.Match("- " + Subnet, out)
  if err != nil || (Action == "add" && matched) || (Action =="remove" && !matched) {
    return
  }

  _, err = ExecuteYggdrasilCtl(Action + "localsubnet", "subnet=" + Subnet)
  if err != nil {
    return
  }

  return
}

func GetSelfAddress() (err error, address string) {
  out, err := ExecuteYggdrasilCtl("-v","getSelf")
  if err != nil {
    return
  }

  re := regexp.MustCompile(`(?m)^IPv6 address: (.*?)$`)
  match := re.FindStringSubmatch(string(out))

  if len(match) < 2 {
    err = fmt.Errorf("Unable to parse yggdrasilctl output: %s", string(out))
    return
  }

  address = match[1]

  return
}

func GetSelfPublicKey() (err error, publicKey string) {
  out, err := ExecuteYggdrasilCtl("-v","getSelf")
  if err != nil {
    return
  }

  re := regexp.MustCompile(`(?m)^Public encryption key: (.*?)$`)
  match := re.FindStringSubmatch(string(out))

  if len(match) < 2 {
    err = fmt.Errorf("Unable to parse yggdrasilctl output: %s", string(out))
    return
  }

  publicKey = match[1]

  return
}

func HandleError(err error, terminateOnFail bool) {
  if err != nil {
    if !Quiet {
      fmt.Printf("[ FAIL ]\n")
      if terminateOnFail {
        os.Exit(1)
      }
    }
    fmt.Printf("-> %s\n", err)
  } else {
    if !Quiet {
      fmt.Printf("[ ok ]\n")
    }
  }
}

func SetupLogWriter() {
  // Initialize our own LogWriter that right justifies all lines at 70 characters
  // and removes the trailing newline from log statements. Used for status lines
  // where we want to write something, then execute a command, and follow with
  // [ok] or [FAIL] on the same line.
  log.SetFlags(0)
  log.SetOutput(new(LogWriter))
}
