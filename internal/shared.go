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
	return tunnelIPWorker("Add", IPAddress, NetMask)
}

func removeTunnelIP(IPAddress string, NetMask int) (err error) {
	return tunnelIPWorker("Del", IPAddress, NetMask)
}

func tunnelIPWorker(action string, IPAddress string, NetMask int) (err error) {
	cmd := viper.GetString("ListTunnelRouteCommand")
	cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", viper.GetString("YggdrasilInterface"), -1)

	out, err := exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	found := strings.Index(string(out), IPAddress+"/"+strconv.Itoa(NetMask))

	if (action == "Add" && found == -1) || (action == "Del" && found != -1) {
		cmd = viper.GetString(action + "TunnelRouteCommand")
		cmd = strings.Replace(cmd, "%%IPAddress%%", IPAddress, -1)
		cmd = strings.Replace(cmd, "%%NetMask%%", strconv.Itoa(NetMask), -1)
		cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", viper.GetString("YggdrasilInterface"), -1)
		_, err = exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).Output()
		if err != nil {
			err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
			return
		}
	}
	return
}

func addRemoteSubnet(Subnet string, PublicKey string) (err error) {
	return remoteSubnetWorker("Add", Subnet, PublicKey)
}

func removeRemoteSubnet(Subnet string, PublicKey string) (err error) {
	return remoteSubnetWorker("Del", Subnet, PublicKey)
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
	if (matched && Action == "Add") || (!matched && Action == "Del") {
		// We don't need to do anything
		return
	}

	cmd := viper.GetString("Gateway" + Action + "RemoteSubnetCommand")
	cmd = strings.Replace(cmd, "%%Subnet%%", Subnet, -1)
	cmd = strings.Replace(cmd, "%%ClientPublicKey%%", PublicKey, -1)

	command := exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd)
	err = command.Run()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
	}

	return
}

// addPeerRoute adds a route for an yggdrasil peer. It runs the command
//   ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
func addPeerRoute(peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	return peerRouteWorker("Add", peer, defaultGatewayIP, defaultGatewayDevice)
}

// removePeerRoute removes a route for an yggdrasil peer. It runs the command
//   ip ro del <peer_ip>
func removePeerRoute(peer string) (err error) {
	return peerRouteWorker("Del", peer, "", "")
}

func peerRouteWorker(action string, peer string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	cmd := viper.GetString(action + "PeerRouteListCommand")
	cmd = strings.Replace(cmd, "%%Peer%%", peer, -1)
	if action == "Add" {
		// defaultGatewayIP and defaultGatewayDevice are only set when adding
		cmd = strings.Replace(cmd, "%%DefaultGatewayIP%%", defaultGatewayIP, -1)
		cmd = strings.Replace(cmd, "%%DefaultGatewayDevice%%", defaultGatewayDevice, -1)
	}

	out, err := exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	if (action == "Add" && strings.TrimSpace(string(out)) == peer) || (action == "Del" && len(out) == 1) {
		// Nothing to do!
		return
	}

	cmd = viper.GetString(action + "PeerRouteCommand")
	cmd = strings.Replace(cmd, "%%Peer%%", peer, -1)
	if action == "Add" {
		// defaultGatewayIP and defaultGatewayDevice are only set when adding
		cmd = strings.Replace(cmd, "%%DefaultGatewayIP%%", defaultGatewayIP, -1)
		cmd = strings.Replace(cmd, "%%DefaultGatewayDevice%%", defaultGatewayDevice, -1)
	}
	_, err = exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
		return
	}
	return
}

// addDefaultGateway adds a default route.
func addDefaultGateway(clientGateway string) (err error) {
	return defaultGatewayWorker("Add", clientGateway)
}

// removeDefaultGateway removes a default route.
func removeDefaultGateway(clientGateway string) (err error) {
	return defaultGatewayWorker("Del", clientGateway)
}

func defaultGatewayWorker(action string, clientGateway string) (err error) {
	cmd := viper.GetString(action + "DefaultGatewayCommand")
	cmd = strings.Replace(cmd, "%%ClientGateway%%", clientGateway, -1)

	_, err = exec.Command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err)
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
		re := regexp.MustCompile(` .*?://(.*):\d+? `)
		match := re.FindStringSubmatch(strings.TrimSpace(l))
		if len(match) < 1 {
			err = fmt.Errorf("Unable to parse yggdrasilctl output: %s", l)
			return
		}
		if strings.IndexByte(match[1], '%') != -1 {
			// Local IPv6 address like [fe80::42:acff:fe11:2%docker0]
			continue
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

func viperLoadSharedDefaults() {
	viper.SetDefault("Shell", "/bin/sh")
	viper.SetDefault("ShellCommandArg", "-c")
	viper.SetDefault("ListTunnelRouteCommand", "ip addr list %%YggdrasilInterface%%")
	viper.SetDefault("AddTunnelRouteCommand", "ip addr add %%IPAddress%%/%%NetMask%% dev %%YggdrasilInterface%%")
	viper.SetDefault("DelTunnelRouteCommand", "ip addr del %%IPAddress%%/%%NetMask%% dev %%YggdrasilInterface%%")
	viper.SetDefault("AddPeerRouteListCommand", "ip ro list %%Peer%% via %%DefaultGatewayIP%% dev %%DefaultGatewayDevice%%")
	viper.SetDefault("DelPeerRouteListCommand", "ip ro list %%Peer%%")
	viper.SetDefault("AddPeerRouteCommand", "ip ro add %%Peer%% via %%DefaultGatewayIP%% dev %%DefaultGatewayDevice%%")
	viper.SetDefault("DelPeerRouteCommand", "ip ro del %%Peer%%")
	viper.SetDefault("GatewayAddRemoteSubnetCommand", "yggdrasilctl addremotesubnet subnet=%%Subnet%% box_pub_key=%%ClientPublicKey%%")
	viper.SetDefault("GatewayDelRemoteSubnetCommand", "yggdrasilctl removeremotesubnet subnet=%%Subnet%% box_pub_key=%%ClientPublicKey%%")
	viper.SetDefault("AddDefaultGatewayCommand", "ip ro add default via %%ClientGateway%%")
	viper.SetDefault("DelDefaultGatewayCommand", "ip ro del default via %%ClientGateway%%")
}
