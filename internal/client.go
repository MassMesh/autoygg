package internal

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/robfig/cron/v3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func clientUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
autoygg-client is a tool to register an Yggdrasil node with a gateway for internet egress.

Options:
`)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
}

func doPostRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string) (response []byte) {
	validActions := map[string]bool{
		"register": true,
		"renew":    true,
		"release":  true,
	}
	if !validActions[action] {
		clientUsage(fs)
		Fatal("Invalid action: " + action)
	}
	var r registration
	var err error
	r.PublicKey, err = getSelfPublicKey()
	if err != nil {
		Fatal(err)
	}
	req, err := json.Marshal(r)
	if err != nil {
		Fatal(err)
	}

	resp, err := http.Post("http://["+gatewayHost+"]:"+gatewayPort+"/"+action, "application/json", bytes.NewBuffer(req))
	if err != nil {
		clientUsage(fs)
		Fatal(err)
	}
	defer resp.Body.Close()

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		Fatal(err)
	}

	return
}

func clientSetupRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDevice string) (err error) {
	log.Printf("Enabling Yggdrasil tunnel routing")
	err = enableTunnelRouting()
	handleError(err, false)
	if err != nil {
		return
	}

	log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
	err = addLocalSubnet("0.0.0.0/0")
	handleError(err, false)

	log.Printf("Adding tunnel IP %s/%d", clientIP, clientNetMask)
	err = addTunnelIP(clientIP, clientNetMask)
	handleError(err, false)

	log.Printf("Adding Yggdrasil remote subnet 0.0.0.0/0")
	err = addRemoteSubnet("0.0.0.0/0", publicKey)
	handleError(err, false)

	// Make sure we route traffic to our Yggdrasil peer(s) to the wan default gateway
	log.Printf("Getting Yggdrasil peers")
	peers, err := yggdrasilPeers()
	handleError(err, false)

	for _, p := range peers {
		// ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
		log.Printf("Adding Yggdrasil peer route for %s via %s", p, defaultGatewayIP)
		err = addPeerRoute(p, defaultGatewayIP, defaultGatewayDevice)
		handleError(err, false)
		if err != nil {
			// If we can't add a route for all yggdrasil peers, something is really wrong and we should abort.
			// Because if we change the default gateway, we will be cutting ourselves off from the internet.
			return
		}
	}

	log.Printf("Adding default gateway pointing at %s", clientGateway)
	err = addDefaultGateway(clientGateway)
	handleError(err, false)

	// FIXME TODO:
	// * discover wan_gw and wan_dev if not specified via cli, and do the ip ro add thing
	// * replace default route, test connectivity, if fail, rollback?
	return
}

func clientTearDownRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string) (err error) {
	log.Printf("Removing default gateway pointing at %s", clientGateway)
	err = removeDefaultGateway(clientGateway)
	handleError(err, false)

	log.Printf("Getting Yggdrasil peers")
	peers, err := yggdrasilPeers()
	handleError(err, false)

	for _, p := range peers {
		log.Printf("Removing Yggdrasil peer route for %s", p)
		err = removePeerRoute(p)
		handleError(err, false)
	}

	log.Printf("Removing Yggdrasil remote subnet 0.0.0.0/0")
	err = removeRemoteSubnet("0.0.0.0/0", publicKey)
	handleError(err, false)

	log.Printf("Removing tunnel IP %s/%d", clientIP, clientNetMask)
	err = removeTunnelIP(clientIP, clientNetMask)
	handleError(err, false)

	log.Printf("Removing Yggdrasil local subnet 0.0.0.0/0")
	err = removeLocalSubnet("0.0.0.0/0")
	handleError(err, false)

	log.Printf("Disabling Yggdrasil tunnel routing")
	err = disableTunnelRouting()
	handleError(err, false)

	return
}

func clientLoadConfig(path string) {
	config := "client"
	if viper.Get("CONFIG") != nil {
		config = viper.Get("CONFIG").(string)
	}

	// Load the main config file
	viper.SetConfigType("yaml")
	viper.SetConfigName(config)
	if path == "" {
		viper.AddConfigPath("/etc/autoygg/")
		viper.AddConfigPath("$HOME/.autoygg")
		viper.AddConfigPath(".")
	} else {
		// For testing
		viper.AddConfigPath(path)
	}
	err := viper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		// The client config file is optional
		err = nil
	} else if err != nil {
		Fatal(fmt.Sprintln("Fatal error reading config file:", err.Error()))
	}
}

func clientCreateFlagSet() (fs *flag.FlagSet) {
	fs = flag.NewFlagSet("Autoygg", flag.ContinueOnError)
	fs.Usage = func() { clientUsage(fs) }

	fs.Bool("daemon", true, "Run in daemon mode. The client will automatically renew its lease before it expires.")
	fs.String("gatewayHost", "", "Yggdrasil IP address of the gateway host")
	fs.String("gatewayPort", "8080", "port of the gateway daemon")
	fs.String("defaultGatewayIP", "", "LAN default gateway IP address (autodiscovered by default)")
	fs.String("defaultGatewayDev", "", "LAN default gateway device (autodiscovered by default)")
	fs.String("yggdrasilInterface", "tun0", "Yggdrasil tunnel interface")
	fs.String("action", "register", "action (register/renew/release)")
	fs.Bool("debug", false, "debug output")
	fs.Bool("quiet", false, "suppress non-error output")
	fs.Bool("dumpConfig", false, "dump the configuration that would be used by autoygg-client and exit")
	fs.Bool("json", false, "dump the configuration in json format, rather than yaml (only relevant when used with --dumpConfig)")
	fs.Bool("complete", false, "dump the complete configuration (default false, only relevant when used with --dumpConfig)")
	fs.Bool("useConfig", false, "read configuration from stdin")
	fs.Bool("help", false, "print usage and exit")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		Fatal(err)
	}

	viperLoadSharedDefaults()

	err = viper.BindPFlags(fs)
	if err != nil {
		Fatal(err)
	}

	return
}

func renewLease(fs *flag.FlagSet) {
	doRequest(fs, "renew", viper.GetString("GatewayHost"), viper.GetString("GatewayPort"))
}

func doRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string) (r registration) {
	log.Printf("Sending `" + action + "` request to autoygg")
	response := doPostRequest(fs, action, gatewayHost, gatewayPort)
	debug("Raw server response:\n\n%s\n\n", string(response))
	err := json.Unmarshal(response, &r)
	handleError(err, false)
	if err != nil {
		if viper.GetString("Action") == "release" {
			// Do not abort when we are trying to release a lease
			fmt.Println(err)
		} else {
			Fatal(err)
		}
	}
	return
}

// ClientMain is the main() function for the client program
func ClientMain() {
	setupLogWriters()

	fs := clientCreateFlagSet()

	if viper.GetBool("UseConfig") {
		viper.SetConfigType("yaml")
		viper.SetConfigName("client")
		// Read the configuration from stdin. Used on openwrt.
		err := viper.ReadConfig(os.Stdin)
		if err != nil {
			Fatal(err)
		}
	} else {
		clientLoadConfig("")
	}

	if viper.GetBool("Help") {
		clientUsage(fs)
		os.Exit(0)
	}

	if viper.GetBool("DumpConfig") {
		fmt.Print(dumpConfiguration("client"))
		os.Exit(0)
	}

	if viper.GetString("GatewayHost") == "" || viper.GetString("Action") == "" {
		clientUsage(fs)
		os.Exit(0)
	}

	if viper.GetBool("Debug") {
		debug = debugLog.Printf
	}

	r := doRequest(fs, viper.GetString("Action"), viper.GetString("GatewayHost"), viper.GetString("GatewayPort"))
	if r.Error != "" {
		Fatal(r.Error)
	}

	var err error

	if viper.GetString("Action") == "release" {
		err = clientTearDownRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey)
	} else {
		gatewayDev := viper.GetString("DefaultGatewayDev")
		gatewayIP := viper.GetString("DefaultGatewayIP")
		if gatewayIP == "" {
			tmpDev, tmpIP, err := DiscoverGateway()
			if err != nil {
				Fatal(err)
			}
			gatewayIP = tmpIP.String()
			gatewayDev = tmpDev
		}
		err = clientSetupRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, gatewayIP, gatewayDev)
	}
	if err != nil {
		Fatal(err)
	}

	if viper.GetBool("Daemon") && viper.GetString("Action") == "register" {
		log.Printf("Set up cron job to renew lease every 30 minutes")
		c := cron.New()
		_, err := c.AddFunc("CRON_TZ=UTC */30 * * * *", func() { renewLease(fs) })
		handleError(err, false)
		if err != nil {
			Fatal("Couldn't set up cron job!")
		}
		go c.Start()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Print("\r") // Overwrite any ^C that may have been printed on the screen
		doRequest(fs, "release", viper.GetString("GatewayHost"), viper.GetString("GatewayPort"))
		_ = clientTearDownRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey)
	}
}

// DiscoverGateway returns the device and IP of the default network gateway
// borrowed from https://github.com/jackpal/gateway (3-clause BSD)
// changed to return the gateway device as well
func DiscoverGateway() (dev string, ip net.IP, err error) {
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
	return parseLinuxProcNetRoute(bytes)
}

// borrowed from https://github.com/jackpal/gateway (3-clause BSD)
// changed to return the gateway device as well
func parseLinuxProcNetRoute(f []byte) (string, net.IP, error) {
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
	if scanner.Scan() {
		// Skip header line
		if !scanner.Scan() {
			return "", nil, errors.New("Invalid linux route file")
		}

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

		// format net.IP to dotted ipV4 string
		return tokens[devfield], net.IP(ipd32), nil
	}
	return "", nil, errors.New("Failed to parse linux route file")
}
