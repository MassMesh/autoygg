package internal

import (
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var debug bool
var enablePrometheus bool

type logWriter struct {
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	if !viper.GetBool("Quiet") {
		// Strip the last character, it's a newline!
		return fmt.Printf("%-70s", string(bytes[:len(bytes)-1]))
	}
	return 0, nil
}

type info struct {
	GatewayOwner         string
	Description          string
	RegistrationRequired bool
}

// State:
// pending: needs human approval
// open: ready for the yggdrasil goroutine to execute
// success: all set
// fail: yggdrasil goroutine reported failure
// removed: yggdrasil registration removed, pending deletion
type registration struct {
	gorm.Model
	State            string
	GatewayPublicKey string
	PublicKey        string
	YggIP            string // The Yggdrasil IP address
	ClientIP         string // The tunnel IP address assigned to the client
	ClientNetMask    int    // The tunnel netmask
	ClientGateway    string
	ClientInfo       string
	LeaseExpires     time.Time
	Error            string
}

// Fatal error. Do not call this from the server code after the
// initialization phase.
func Fatal(err interface{}) {
	// Reset the log settings to the default
	log.SetFlags(log.LstdFlags)
	log.SetOutput(os.Stderr)
	log.Fatal("Error: ", err)
}

func addTunnelIP(IPAddress string, NetMask int) (err error) {
	return tunnelIPWorker("add", IPAddress, NetMask)
}

func removeTunnelIP(IPAddress string, NetMask int) (err error) {
	return tunnelIPWorker("del", IPAddress, NetMask)
}

func tunnelIPWorker(action string, IPAddress string, NetMask int) (err error) {
	out, err := exec.Command("ip", "addr", "list", "tun0").Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `ip addr list tun0`: %s", err)
		return
	}

	found := strings.Index(string(out), IPAddress+"/"+strconv.Itoa(NetMask))

	if (action == "add" && found == -1) || (action == "del" && found != -1) {
		_, err = exec.Command("ip", "addr", action, IPAddress+"/"+strconv.Itoa(NetMask), "dev", "tun0").Output()
		if err != nil {
			err = fmt.Errorf("Unable to run `ip addr %s %s/%d dev tun0`: %s", action, IPAddress, NetMask, err)
			return
		}
	}
	return
}

func addRemoteSubnet(Subnet string, PublicKey string) (err error) {
	return remoteSubnetWorker("Add", Subnet, PublicKey)
}

func removeRemoteSubnet(Subnet string, PublicKey string) (err error) {
	return remoteSubnetWorker("Remove", Subnet, PublicKey)
}

func remoteSubnetWorker(Action string, Subnet string, PublicKey string) (err error) {
	out, err := executeYggdrasilCtl("getroutes")
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

	commandSlice := strings.Split(command, " ")
	cmd := exec.Command(commandSlice[0], commandSlice[1:]...)
	err = cmd.Run()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s`: %s", command, err)
	}

	return
}

// addPeerRoute adds a route for an yggdrasil peer. It runs the command
//   ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
func addPeerRoute(peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	return peerRouteWorker("add", peer, defaultGatewayIP, defaultGatewayDevice)
}

// removePeerRoute removes a route for an yggdrasil peer. It runs the command
//   ip ro del <peer_ip> via <wan_gw> dev <wan_dev>
func removePeerRoute(peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	return peerRouteWorker("del", peer, defaultGatewayIP, defaultGatewayDevice)
}

func peerRouteWorker(action string, peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	cmdArgs := []string{"ro", "list", peer, "via", defaultGatewayIP, "dev", defaultGatewayDevice}
	out, err := exec.Command("ip", cmdArgs...).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs, " "), err)
		return
	}
	if (action == "add" && strings.TrimSpace(string(out)) == peer) || (action == "del" && len(out) == 1) {
		// Nothing to do!
		return
	}

	cmdArgs = []string{"ro", action, peer, "via", defaultGatewayIP, "dev", defaultGatewayDevice}
	_, err = exec.Command("ip", cmdArgs...).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs, " "), err)
	}
	return
}

// addDefaultGateway adds a default route. It runs the command
//   ip ro add default via <ygg_gateway_ip>
func addDefaultGateway(clientGateway string) (err error) {
	return defaultGatewayWorker("add", clientGateway)
}

func removeDefaultGateway(clientGateway string) (err error) {
	return defaultGatewayWorker("del", clientGateway)
}

func defaultGatewayWorker(action string, clientGateway string) (err error) {
	cmdArgs := []string{"ro", action, "default", "via", clientGateway}
	_, err = exec.Command("ip", cmdArgs...).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `ip %s`: %s", strings.Join(cmdArgs, " "), err)
	}
	return
}

// yggdrasilPeers returns the list of yggdrasil peers. It parses the output of
// `yggdrasilctl getPeers`, e.g.:
//                                        bytes_recvd    bytes_sent    endpoint                                      port  proto  uptime
//200:40ff:e447:5bb6:13ee:8a9a:e71d:b6ee  817789         0             tcp://[fe80::109a:683d:a72:c4f5%wlan0]:45279  2     tcp    11:16:30
//201:44e1:28f0:af3c:cf1b:6e2a:79bd:44b0  14578499       14497520      tcp://50.236.201.218:56088                    3     tcp    11:15:45
func yggdrasilPeers() (peers []string, err error) {
	selfAddress, err := getSelfAddress()
	if err != nil {
		return
	}

	out, err := executeYggdrasilCtl("getPeers")
	if err != nil {
		return
	}
	var matched bool
	re, err := regexp.Compile("^2")
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(out), "\n") {
		matched = re.MatchString(l)
		if !matched {
			// Not a line that starts with a peer address
			continue
		}
		if strings.HasPrefix(l, selfAddress) {
			// Skip ourselves
			continue
		}

		re := regexp.MustCompile(` .*?://(.*?):.* `)
		match := re.FindStringSubmatch(l)
		if len(match) < 1 {
			err = fmt.Errorf("Unable to parse yggdrasilctl output: %s", l)
			return
		}
		peers = append(peers, match[1])
	}
	return
}

func executeYggdrasilCtl(cmd ...string) (out []byte, err error) {
	out, err = exec.Command("yggdrasilctl", cmd...).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `yggdrasilctl %s`: %s", strings.Join(cmd, " "), err)
	}
	return
}

func enableTunnelRouting() (err error) {
	return tunnelRoutingWorker("true")
}

func disableTunnelRouting() (err error) {
	return tunnelRoutingWorker("false")
}

func tunnelRoutingWorker(State string) (err error) {
	out, err := executeYggdrasilCtl("gettunnelrouting")
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

	_, err = executeYggdrasilCtl("settunnelrouting", "enabled="+State)
	if err != nil {
		return
	}

	return
}

func addLocalSubnet(Subnet string) (err error) {
	return localSubnetWorker("add", Subnet)
}

func removeLocalSubnet(Subnet string) (err error) {
	return localSubnetWorker("remove", Subnet)
}

func localSubnetWorker(Action string, Subnet string) (err error) {
	out, err := executeYggdrasilCtl("getsourcesubnets")
	if err != nil {
		return
	}

	matched, err := regexp.Match("- "+Subnet, out)
	if err != nil || (Action == "add" && matched) || (Action == "remove" && !matched) {
		return
	}

	_, err = executeYggdrasilCtl(Action+"localsubnet", "subnet="+Subnet)
	if err != nil {
		return
	}

	return
}

func getSelfAddress() (address string, err error) {
	out, err := executeYggdrasilCtl("-v", "getSelf")
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

func getSelfPublicKey() (publicKey string, err error) {
	out, err := executeYggdrasilCtl("-v", "getSelf")
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

func handleError(err error, terminateOnFail bool) {
	if err != nil {
		if !viper.GetBool("Quiet") {
			fmt.Printf("[ FAIL ]\n")
			if terminateOnFail {
				os.Exit(1)
			}
		}
		fmt.Printf("-> %s\n", err)
	} else {
		if !viper.GetBool("Quiet") {
			fmt.Printf("[ ok ]\n")
		}
	}
}

func setupLogWriter() {
	// Initialize our own logWriter that right justifies all lines at 70 characters
	// and removes the trailing newline from log statements. Used for status lines
	// where we want to write something, then execute a command, and follow with
	// [ok] or [FAIL] on the same line.
	log.SetFlags(0)
	log.SetOutput(new(logWriter))
}

func dumpConfiguration() {
	configMap := viper.AllSettings()
	delete(configMap, "help") // do not include the "help" flag in the config dump
	b, err := yaml.Marshal(configMap)
	if err != nil {
		Fatal(err)
	}
	fmt.Print("\nConfiguration as loaded from the config file and any command line arguments:\n\n")
	fmt.Println(string(b))
	os.Exit(0)
}
