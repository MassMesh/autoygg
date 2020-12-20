package internal

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Debug output goes nowhere by default
	debug = func(string, ...interface{}) {}
	// Set up a *log.Logger for debug output
	debugLog         = log.New(os.Stderr, "DEBUG: ", log.LstdFlags)
	enablePrometheus bool
	version          = "dev"
)

type logWriter struct {
	quiet       bool
	interactive bool
}

func command(name string, arg ...string) (cmd *exec.Cmd) {
	debug("%s %v", name, strings.NewReplacer("[", "", "]", "").Replace(fmt.Sprintf("%v", arg)))
	cmd = exec.Command(name, arg...)
	return
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	if !writer.interactive && !writer.quiet {
		return fmt.Printf("%s", string(bytes))
	} else if !writer.quiet {
		// Strip the last character, it's a newline!
		return fmt.Printf("%-70s", string(bytes[:len(bytes)-1]))
	}
	return 0, nil
}

type info struct {
	GatewayOwner        string
	Description         string
	Network             string
	Location            string
	GatewayInfoURL      string
	SoftwareVersion     string
	RequireRegistration bool
	RequireApproval     bool
	AccessListEnabled   bool
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
	ClientName       string // Registration name (optional)
	ClientEmail      string // Registration email (optional)
	ClientPhone      string // Registration phone (optional)
	ClientVersion    string // Autoygg client software version
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

func addTunnelIP(lViper *viper.Viper, address string, netMask int) error {
	return tunnelIPWorker(lViper, "Add", address, netMask)
}

func removeTunnelIP(lViper *viper.Viper, address string, netMask int) error {
	return tunnelIPWorker(lViper, "Del", address, netMask)
}

func tunnelIPWorker(lViper *viper.Viper, action string, address string, netMask int) (err error) {
	cmd := lViper.GetString("ListTunnelRouteCommand")
	cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", lViper.GetString("YggdrasilInterface"), -1)

	out, err := command(lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	found := strings.Index(string(out), address+"/"+strconv.Itoa(netMask))

	if (action == "Add" && found == -1) || (action == "Del" && found != -1) {
		cmd = lViper.GetString(action + "TunnelRouteCommand")
		cmd = strings.Replace(cmd, "%%IPAddress%%", address, -1)
		cmd = strings.Replace(cmd, "%%NetMask%%", strconv.Itoa(netMask), -1)
		cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", lViper.GetString("YggdrasilInterface"), -1)
		out, err = command(lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("Unable to run `%s %s %s`: %s (%s)", lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd, err, out)
			return
		}
	}
	if action == "Add" {
		configChanges = append(configChanges, configChange{Name: "TunnelIP", OldVal: "", NewVal: address + "/" + string(netMask)})
	}

	return
}

func addRemoteSubnet(lViper *viper.Viper, subnet string, publicKey string) error {
	return remoteSubnetWorker(lViper, "Add", subnet, publicKey)
}

func removeRemoteSubnet(lViper *viper.Viper, subnet string, publicKey string) error {
	return remoteSubnetWorker(lViper, "Del", subnet, publicKey)
}

func remoteSubnetWorker(lViper *viper.Viper, action string, subnet string, publicKey string) (err error) {
	out, err := executeYggdrasilCtl("getroutes")
	if err != nil {
		return
	}
	matched, err := regexp.Match(subnet, out)
	if err != nil {
		return
	}
	if (matched && action == "Add") || (!matched && action == "Del") {
		// We don't need to do anything
		return
	}

	cmd := lViper.GetString("Gateway" + action + "RemoteSubnetCommand")
	cmd = strings.Replace(cmd, "%%Subnet%%", subnet, -1)
	cmd = strings.Replace(cmd, "%%ClientPublicKey%%", publicKey, -1)

	command := command(lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd)
	err = command.Run()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", lViper.GetString("Shell"), lViper.GetString("ShellCommandArg"), cmd, err)
	}

	return
}

// addPeerRoute adds a route for an yggdrasil peer. It runs the command
//   ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
func addPeerRoute(peer string, defaultGatewayIP string, defaultGatewayDevice string) (bool, error) {
	return peerRouteWorker("Add", peer, defaultGatewayIP, defaultGatewayDevice)
}

// removePeerRoute removes a route for an yggdrasil peer. It runs the command
//   ip ro del <peer_ip>
func removePeerRoute(peer string) (bool, error) {
	return peerRouteWorker("Del", peer, "", "")
}

func peerRouteWorker(action string, peer string, defaultGatewayIP string, defaultGatewayDevice string) (change bool, err error) {
	cmd := cViper.GetString(action + "PeerRouteListCommand")
	cmd = strings.Replace(cmd, "%%Peer%%", peer, -1)
	if action == "Add" {
		// defaultGatewayIP and defaultGatewayDevice are only set when adding
		cmd = strings.Replace(cmd, "%%DefaultGatewayIP%%", defaultGatewayIP, -1)
		cmd = strings.Replace(cmd, "%%DefaultGatewayDevice%%", defaultGatewayDevice, -1)
	}

	out, err := command(cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	matched, err := regexp.Match(`^`+peer, out)
	if err != nil {
		return
	}
	if action == "Add" && matched {
		// Nothing to do!
		return
	}

	if action == "Del" && !matched {
		// Nothing to do!
		return change, err
	}

	cmd = cViper.GetString(action + "PeerRouteCommand")
	cmd = strings.Replace(cmd, "%%Peer%%", peer, -1)
	if action == "Add" {
		// defaultGatewayIP and defaultGatewayDevice are only set when adding
		cmd = strings.Replace(cmd, "%%DefaultGatewayIP%%", defaultGatewayIP, -1)
		cmd = strings.Replace(cmd, "%%DefaultGatewayDevice%%", defaultGatewayDevice, -1)
	}
	_, err = command(cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	// Flush the route cache
	cmdFlushRouteCache := "ip route flush cache"
	_, err = command(cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmdFlushRouteCache).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmdFlushRouteCache, err)
		return
	}
	change = true

	return
}

// addDefaultGateway adds a default route.
func addDefaultGateway(clientGateway string) error {
	return defaultGatewayWorker(clientGateway)
}

// removeDefaultGateway removes a default route.
func removeDefaultGateway(clientGateway string) error {
	return defaultGatewayWorker(clientGateway)
}

func defaultGatewayWorker(clientGateway string) (err error) {
	var cmd string
	if clientGateway != "0.0.0.0" {
		cmd = cViper.GetString("DefaultGatewayCommand")
	} else {
		// We're removing the default gateway that we installed, and there was no
		// default gateway originally, so we restore that situation.
		cmd = cViper.GetString("DelDefaultGatewayCommand")
	}
	cmd = strings.Replace(cmd, "%%ClientGateway%%", clientGateway, -1)

	_, err = command(cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd).Output()
	if err != nil {
		// We can't do a ip ro list default command, that returns all routes. Instead, just
		// check for a duplicate route error here and suppress it.
		matched, _ := regexp.Match(`File exists`, err.(*exec.ExitError).Stderr)
		if matched {
			// The route already exists
			err = nil
			return
		}
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), cmd, err)
	}
	return
}

// yggdrasilPeers returns the list of yggdrasil peers. It parses the output of
// `yggdrasilctl getPeers`, e.g.:
//                                        bytes_recvd    bytes_sent    endpoint                                      port  proto  uptime
//200:40ff:e447:5bb6:13ee:8a9a:e71d:b6ee  817789         0             tcp://[fe80::109a:683d:a72:c4f5%wlan0]:45279  2     tcp    11:16:30
//201:44e1:28f0:af3c:cf1b:6e2a:79bd:44b0  14578499       14497520      tcp://50.236.201.218:56088                    3     tcp    11:15:45
func yggdrasilPeers() (peers []string, err error) {

	peers, err = yggdrasilRunningPeers(peers)
	if err != nil {
		return
	}
	peers, err = yggdrasilConfigPeers(peers)
	if err != nil {
		return
	}
	// Deduplicate the peer list
	peerMap := make(map[string]bool)
	for _, p := range peers {
		peerMap[p] = true
	}
	var dedupPeers []string
	for p := range peerMap {
		dedupPeers = append(dedupPeers, p)
	}

	return dedupPeers, nil
}

func yggdrasilRunningPeers(startingPeers []string) (peers []string, err error) {
	peers = startingPeers
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
	peerRe := regexp.MustCompile(` .*?://(.*):\d+? `)
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
		match := peerRe.FindStringSubmatch(strings.TrimSpace(l))
		if len(match) < 1 {
			err = fmt.Errorf("Unable to parse yggdrasilctl output: %s", l)
			return
		}
		if strings.Contains(match[1], ":") {
			// Local IPv6 address like [fe80::42:acff:fe11:2%docker0]
			// Or any other IPv6 address. Using ip.To4() == nil is not good enough,
			// cf. https://github.com/miekg/dns/pull/923
			continue
		}
		peers = append(peers, match[1])
	}
	return
}

func yggdrasilConfigPeers(startingPeers []string) (peers []string, err error) {
	/* Yggdrasilctl will not list peers for which a circuit is not currently
	   established. To work around this, add all peers defined in the config
	   file. This is mostly a backstop against yggdrasil bugs; we don't ever
	   want to route non-ygg traffic for our peers via the yggdrasil tunnel.
	*/
	peers = startingPeers
	peerRe := regexp.MustCompile(` .*?://(.*):\d+? `)
	var conf []byte
	err = command("which", "ygguci").Run()
	if err == nil {
		// Running on openwrt.
		debug("Detected OpenWrt, converting `ygguci get` to yggdrasil configuration")
		var rawconf []byte
		rawconf, err = command("ygguci", "get").Output()
		if err != nil {
			err = fmt.Errorf("Unable to run command `ygguci get`: %s", err)
			return
		}
		cmd := command("yggdrasil", "-useconf", "-normaliseconf", "-json")
		var stdin io.WriteCloser
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return
		}
		go func() {
			defer stdin.Close()
			_, err := stdin.Write(rawconf)
			if err != nil {
				Fatal(err)
			}
		}()
		conf, err = cmd.Output()
		if err != nil {
			err = fmt.Errorf("Unable to run command `yggdrasil -useconf -normaliseconf -json`: %s", err)
			return
		}
	} else {
		// Running elsewhere. Assume config file is in the standard location.
		conf, err = command("yggdrasil", "-useconffile", "/etc/yggdrasil.conf", "-normaliseconf", "-json").Output()
		if err != nil {
			err = fmt.Errorf("Unable to run command `yggdrasil -useconffile /etc/yggdrasil.conf -normaliseconf -json`: %s", err)
			return
		}
	}
	var config config.NodeConfig
	err = json.Unmarshal(conf, &config)
	if err != nil {
		err = fmt.Errorf("Unable to parse yggdrasil config: %s", conf)
		return
	}
	for _, peer := range config.Peers {
		match := peerRe.FindStringSubmatch(" " + peer + " ")
		if len(match) > 0 {
			peers = append(peers, match[1])
		} else {
			err = fmt.Errorf("Unable to parse peer from yggdrasil config: %s", peer)
			return
		}
	}
	return
}

func executeYggdrasilCtl(cmd ...string) (out []byte, err error) {
	out, err = command("yggdrasilctl", cmd...).Output()
	if err != nil {
		err = fmt.Errorf("Unable to run `yggdrasilctl %s`: %s", strings.Join(cmd, " "), err)
	}
	return
}

func enableTunnelRouting() error {
	return tunnelRoutingWorker(true)
}

func disableTunnelRouting() error {
	return tunnelRoutingWorker(false)
}

func tunnelRoutingWorker(state bool) (err error) {
	out, err := executeYggdrasilCtl("gettunnelrouting")
	if err != nil {
		return
	}

	var matched bool
	if state {
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

	_, err = executeYggdrasilCtl("settunnelrouting", "enabled="+strconv.FormatBool(state))
	if err != nil {
		return
	}
	if state {
		configChanges = append(configChanges, configChange{Name: "TunnelRouting", OldVal: false, NewVal: state})
	}

	return
}

func addLocalSubnet(subnet string) error {
	return localSubnetWorker("add", subnet)
}

func removeLocalSubnet(subnet string) error {
	return localSubnetWorker("remove", subnet)
}

func localSubnetWorker(action string, subnet string) (err error) {
	out, err := executeYggdrasilCtl("getsourcesubnets")
	if err != nil {
		return
	}

	matched, err := regexp.Match("- "+subnet, out)
	if err != nil || (action == "add" && matched) || (action == "remove" && !matched) {
		return
	}

	_, err = executeYggdrasilCtl(action+"localsubnet", "subnet="+subnet)
	if err != nil {
		return
	}
	if action == "add" {
		configChanges = append(configChanges, configChange{Name: "LocalSubnet", OldVal: "", NewVal: subnet})
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

func handleError(err error, lViper *viper.Viper, terminateOnFail bool) {
	if err != nil {
		if !lViper.GetBool("Quiet") {
			fmt.Printf("[ FAIL ]\n")
		}
		fmt.Printf("Error: %s\n", err)
		if terminateOnFail {
			os.Exit(1)
		}
	} else {
		if !lViper.GetBool("Quiet") {
			fmt.Printf("[ ok ]\n")
		}
	}
}

func setupLogWriters(lViper *viper.Viper, interactive bool) {
	// Initialize our own logWriter. In 'interactive mode', it right justifies
	// all lines at 70 characters and removes the trailing newline from log
	// statements. Used for status lines where we want to write something, then
	// execute a command, and follow with [ok] or [FAIL] on the same line.
	log.SetFlags(0)
	writer := new(logWriter)
	writer.quiet = lViper.GetBool("Quiet")
	writer.interactive = interactive
	log.SetOutput(writer)
}

func dumpConfiguration(lViper *viper.Viper, app string) (config string) {
	configMap := lViper.AllSettings()
	delete(configMap, "help")       // do not include the "help" flag in the config dump
	delete(configMap, "dumpconfig") // do not include the "dumpconfig" flag in the config dump
	delete(configMap, "version")    // do not include the "version" flag in the config dump
	if app == "client" {
		delete(configMap, "complete")  // do not include the "complete" flag in the config dump
		delete(configMap, "state")     // do not include the "state" flag in the config dump
		delete(configMap, "useconfig") // do not include the "useconfig" flag in the config dump
		delete(configMap, "useuci")    // do not include the "useuci" flag in the config dump
	}

	var b []byte
	var err error
	var minimalConfigMap map[string]interface{}
	if app == "client" && !lViper.GetBool("Complete") {
		minimalConfigMap = make(map[string]interface{})
		minimalConfigMap["gatewayhost"] = configMap["gatewayhost"]
		minimalConfigMap["gatewayport"] = configMap["gatewayport"]
		minimalConfigMap["yggdrasilinterface"] = configMap["yggdrasilinterface"]
		minimalConfigMap["daemon"] = configMap["daemon"]
		minimalConfigMap["clientname"] = configMap["clientname"]
		minimalConfigMap["clientemail"] = configMap["clientemail"]
		minimalConfigMap["clientphone"] = configMap["clientphone"]
		configMap = minimalConfigMap
	}
	if lViper.GetBool("Json") {
		b, err = json.Marshal(configMap)
	} else {
		b, err = yaml.Marshal(configMap)
	}
	if err != nil {
		Fatal(err)
	}
	config = fmt.Sprintln(string(b))
	return
}

func viperLoadSharedDefaults(lViper *viper.Viper) {
	lViper.SetDefault("StateDir", "/var/lib/autoygg")
	lViper.SetDefault("Shell", "/bin/sh")
	lViper.SetDefault("ShellCommandArg", "-c")
	lViper.SetDefault("ListTunnelRouteCommand", "ip addr list %%YggdrasilInterface%%")
	lViper.SetDefault("AddTunnelRouteCommand", "ip addr add %%IPAddress%%/%%NetMask%% dev %%YggdrasilInterface%%")
	lViper.SetDefault("DelTunnelRouteCommand", "ip addr del %%IPAddress%%/%%NetMask%% dev %%YggdrasilInterface%%")
	lViper.SetDefault("AddPeerRouteListCommand", "ip ro list %%Peer%% via %%DefaultGatewayIP%% dev %%DefaultGatewayDevice%%")
	lViper.SetDefault("DelPeerRouteListCommand", "ip ro list %%Peer%%")
	lViper.SetDefault("AddPeerRouteCommand", "ip ro add %%Peer%% via %%DefaultGatewayIP%% dev %%DefaultGatewayDevice%%")
	lViper.SetDefault("DelPeerRouteCommand", "ip ro del %%Peer%%")
	lViper.SetDefault("GatewayAddRemoteSubnetCommand", "yggdrasilctl addremotesubnet subnet=%%Subnet%% box_pub_key=%%ClientPublicKey%%")
	lViper.SetDefault("GatewayDelRemoteSubnetCommand", "yggdrasilctl removeremotesubnet subnet=%%Subnet%% box_pub_key=%%ClientPublicKey%%")
	lViper.SetDefault("DefaultGatewayCommand", "ip ro replace default via %%ClientGateway%%")
	lViper.SetDefault("DelDefaultGatewayCommand", "ip ro del default")
	lViper.SetDefault("Version", false)
}

// DiscoverLocalGateway returns the device and IP of the default network gateway
// borrowed from https://github.com/jackpal/gateway (3-clause BSD)
// changed to return the gateway device as well
func DiscoverLocalGateway(YggdrasilInterface string) (dev string, ip net.IP, err error) {
	const file = "/proc/net/route"
	f, err := os.Open(file)
	if err != nil {
		return "", nil, fmt.Errorf("Can't access %s", file)
	}
	defer f.Close()

	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return "", nil, fmt.Errorf("Can't read %s", file)
	}
	return parseLinuxProcNetRoute(YggdrasilInterface, bytes)
}

// borrowed from https://github.com/jackpal/gateway (3-clause BSD)
// changed to return the gateway device as well
func parseLinuxProcNetRoute(YggdrasilInterface string, f []byte) (string, net.IP, error) {
	/* /proc/net/route file:
	   Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
	   eno1    00000000    C900A8C0    0003    0   0   100 00000000    0   00
	   eno1    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
	*/
	const (
		sep      = "\t" // field separator
		devfield = 0    // field containing gateway internet device name
		field    = 2    // field containing hex gateway address
	)
	scanner := bufio.NewScanner(bytes.NewReader(f))
	// Skip header line
	if !scanner.Scan() {
		return "", nil, errors.New("Invalid linux route file")
	}
	for scanner.Scan() {
		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		if len(tokens) <= field {
			return "", nil, errors.New("Invalid linux route file")
		}
		gatewayHex := "0x" + tokens[field]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)

		// We want the (original) local gateway, not the Autoygg gateway
		if tokens[devfield] == YggdrasilInterface {
			debug("Skipping %s via %s\n", net.IP(ipd32), tokens[devfield])
			continue
		}
		// If there are any routes that are not attached to a specific interface,
		// like blacklist routes, skip those too
		if tokens[devfield] == "*" {
			debug("Skipping %s via %s\n", net.IP(ipd32), tokens[devfield])
			continue
		}

		// format net.IP to dotted ipV4 string
		debug("Returning %s via %s\n", net.IP(ipd32), tokens[devfield])
		return tokens[devfield], net.IP(ipd32), nil
	}
	return "", nil, errors.New("Failed to parse linux route file")
}
