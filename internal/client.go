package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jpillora/backoff"
	"github.com/robfig/cron/v3"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var cViper *viper.Viper

type state struct {
	State                     string                  `json:"state"`
	DesiredState              string                  `json:"desiredstate"`
	ClientVersion             string                  `json:"clientversion"`
	Error                     string                  `json:"error"`
	GatewayHost               string                  `json:"gatewayhost"`
	GatewayPort               string                  `json:"gatewayport"`
	GatewayPublicKey          string                  `json:"gatewaypublickey"`
	OriginalDefaultGatewayDev string                  `json:"originaldefaultgatewaydevice"`
	OriginalDefaultGatewayIP  string                  `json:"originaldefaultgatewayip"`
	YggdrasilInterface        string                  `json:"yggdrasilinterface"`
	ClientIP                  string                  `json:"clientip"`
	ClientNetMask             int                     `json:"clientnetmask"`
	ClientGateway             string                  `json:"clientgateway"`
	LeaseExpires              time.Time               `json:"leaseexpires"`
	TunnelRouting             bool                    `json:"tunnelrouting"`
	PeerRoutes                map[string]yggPeerRoute `json:"peerroutes"`
}

type yggPeerRoute struct {
	DefaultGatewayIP  string `json:"defaultgatewayip"`
	DefaultGatewayDev string `json:"defaultgatewaydevice"`
}

type errorOutput struct {
	Error string `json:"error"`
}

func logAndExit(message string, exitcode int) {
	Output := errorOutput{
		Error: message,
	}
	text := "Error: " + message + "\n"
	if cViper.GetBool("Json") {
		tmp, err := json.Marshal(Output)
		if err != nil {
			Fatal(err)
		}
		text = string(tmp)
	}
	fmt.Println(text)
	os.Exit(exitcode)
}

func clientUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
autoygg-client is a tool to register an Yggdrasil node with a gateway for internet egress.

Options:
`)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
}

func doRequestWorker(fs *flag.FlagSet, verb string, action string, gatewayHost string, gatewayPort string, i info) (response []byte, err error) {
	validActions := map[string]bool{
		"register": true, // register and request a lease
		"renew":    true, // renew an existing lease
		"release":  true, // release an existing lease
	}
	if !validActions[action] {
		err = errors.New("Invalid action: " + action)
		// Invalid action is a fatal error, abort here
		handleError(err, cViper, true)
	}
	var r registration
	r.PublicKey, err = getSelfPublicKey()
	if err != nil {
		return
	}
	// Only send ClientName, ClientEmail and ClientPhone when registration is required
	if i.RequireRegistration {
		r.ClientName = cViper.GetString("clientname")
		r.ClientEmail = cViper.GetString("clientemail")
		r.ClientPhone = cViper.GetString("clientphone")
	}
	r.ClientVersion = version
	req, err := json.Marshal(r)
	if err != nil {
		return
	}

	var resp *http.Response
	if verb == "post" {
		resp, err = http.Post("http://["+gatewayHost+"]:"+gatewayPort+"/"+action, "application/json", bytes.NewBuffer(req))
	} else {
		resp, err = http.Get("http://[" + gatewayHost + "]:" + gatewayPort + "/" + action)
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()

	response, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	return
}

func clientSetupRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, defaultGatewayIP string, defaultGatewayDev string, State state) (newState state, err error) {
	newState = State
	newState.Error = ""
	log.Printf("Enabling Yggdrasil tunnel routing")
	err = enableTunnelRouting()
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
		saveState(State)
		return
	}
	newState.TunnelRouting = true

	newState.OriginalDefaultGatewayDev = defaultGatewayDev
	newState.OriginalDefaultGatewayIP = defaultGatewayIP

	log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
	err = addLocalSubnet("0.0.0.0/0")
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Adding tunnel IP %s/%d", clientIP, clientNetMask)
	err = addTunnelIP(cViper, clientIP, clientNetMask)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Adding Yggdrasil remote subnet 0.0.0.0/0")
	err = addRemoteSubnet(cViper, "0.0.0.0/0", publicKey)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	// Make sure we route traffic to our Yggdrasil peer(s) to the wan default gateway
	log.Printf("Getting Yggdrasil peers")
	peers, err := yggdrasilPeers()
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	for _, p := range peers {
		// ip ro add <peer_ip> via <wan_gw> dev <wan_dev>
		log.Printf("Adding Yggdrasil peer route for %s via %s", p, defaultGatewayIP)
		var change bool
		change, err = addPeerRoute(p, defaultGatewayIP, defaultGatewayDev)
		handleError(err, cViper, false)
		if err != nil {
			// If we can't add a route for all yggdrasil peers, something is really wrong and we should abort.
			// Because if we change the default gateway, we will be cutting ourselves off from the internet.
			newState.Error += err.Error() + "\n"
			saveState(State)
			return
		}
		if change {
			if newState.PeerRoutes == nil {
				newState.PeerRoutes = make(map[string]yggPeerRoute)
			}
			newState.PeerRoutes[p] = yggPeerRoute{DefaultGatewayIP: defaultGatewayIP, DefaultGatewayDev: defaultGatewayDev}
		}
	}

	log.Printf("Adding default gateway pointing at %s", clientGateway)
	err = addDefaultGateway(clientGateway)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	newState.State = "connected"
	saveState(State)

	// FIXME TODO:
	// * replace default route, test connectivity, if fail, rollback?
	return
}

func clientTearDownRoutes(clientIP string, clientNetMask int, clientGateway string, publicKey string, State state) (newState state, err error) {
	newState = State
	newState.Error = ""
	log.Printf("Removing default gateway pointing at %s", clientGateway)
	err = removeDefaultGateway(State.OriginalDefaultGatewayIP)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Getting Yggdrasil peers from state file")
	handleError(nil, cViper, false)
	for p := range State.PeerRoutes {
		log.Printf("Removing Yggdrasil peer route for %s", p)
		var change bool
		change, err = removePeerRoute(p)
		handleError(err, cViper, false)
		if err != nil {
			newState.Error += err.Error() + "\n"
		}
		if change {
			delete(newState.PeerRoutes, p)
		}
	}

	log.Printf("Removing Yggdrasil remote subnet 0.0.0.0/0")
	err = removeRemoteSubnet(cViper, "0.0.0.0/0", publicKey)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Removing tunnel IP %s/%d", clientIP, clientNetMask)
	err = removeTunnelIP(cViper, clientIP, clientNetMask)
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Removing Yggdrasil local subnet 0.0.0.0/0")
	err = removeLocalSubnet("0.0.0.0/0")
	handleError(err, cViper, false)
	if err != nil {
		newState.Error += err.Error() + "\n"
	}

	log.Printf("Disabling Yggdrasil tunnel routing")
	err = disableTunnelRouting()
	handleError(err, cViper, false)
	newState.TunnelRouting = false
	newState.State = "registered"
	if err != nil {
		newState.Error += err.Error() + "\n"
	}
	saveState(newState)
	return
}

func clientLoadConfig(path string) {
	config := "client"
	if cViper.Get("CONFIG") != nil {
		config = cViper.Get("CONFIG").(string)
	}

	// Load the main config file
	cViper.SetConfigType("yaml")
	cViper.SetConfigName(config)
	if path == "" {
		cViper.AddConfigPath("/etc/autoygg/")
		cViper.AddConfigPath("$HOME/.autoygg")
		cViper.AddConfigPath(".")
	} else {
		// For testing
		cViper.AddConfigPath(path)
	}
	err := cViper.ReadInConfig()
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		// The client config file is optional
		err = nil
	} else if err != nil {
		Fatal(fmt.Sprintln("Fatal error reading config file:", err.Error()))
	}
}

func clientCreateFlagSet(args []string) (fs *flag.FlagSet) {
	fs = flag.NewFlagSet("Autoygg", flag.ContinueOnError)
	fs.Usage = func() { clientUsage(fs) }

	fs.Bool("daemon", true, "Run in daemon mode. The client will automatically renew its lease before it expires.")
	fs.String("gatewayHost", "", "Yggdrasil IP address of the gateway host")
	fs.String("gatewayPort", "8080", "port of the gateway daemon")
	fs.String("defaultGatewayIP", "", "LAN default gateway IP address (autodiscovered by default)")
	fs.String("defaultGatewayDev", "", "LAN default gateway device (autodiscovered by default)")
	fs.String("yggdrasilInterface", "tun0", "Yggdrasil tunnel interface")
	fs.String("action", "register", "action (register/renew/release)")
	fs.String("clientName", "", "your name (optional)")
	fs.String("clientEmail", "", "your e-mail (optional)")
	fs.String("clientPhone", "", "your phone number (optional)")
	fs.Bool("debug", false, "debug output")
	fs.Bool("quiet", false, "suppress non-error output")
	fs.Bool("dumpConfig", false, "dump the configuration that would be used by autoygg-client and exit")
	fs.Bool("json", false, "dump the configuration in json format, rather than yaml (only relevant when used with --dumpConfig)")
	fs.Bool("complete", false, "dump the complete configuration (default false, only relevant when used with --dumpConfig)")
	fs.Bool("useConfig", false, "read configuration from stdin")
	fs.Bool("useUCI", false, "read configuration by executing 'autoygguci get'")
	fs.Bool("state", false, "print current state in json format")
	fs.Bool("help", false, "print usage and exit")
	fs.Bool("version", false, "print version and exit")

	err := fs.Parse(args)
	if err != nil {
		Fatal(err)
	}

	viperLoadSharedDefaults(cViper)

	err = cViper.BindPFlags(fs)
	if err != nil {
		Fatal(err)
	}

	return
}

func renewLease(fs *flag.FlagSet, State state) (newState state) {
	_, newState, _ = doRequest(fs, "renew", cViper.GetString("GatewayHost"), cViper.GetString("GatewayPort"), State)
	return
}

func doInfoRequest(fs *flag.FlagSet, gatewayHost string, gatewayPort string) (i info, err error) {
	client := http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 500 * time.Millisecond,
			}).Dial,
		},
	}

	resp, err := client.Get("http://[" + gatewayHost + "]:" + gatewayPort + "/info")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(response, &i)
	return
}

func doRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string, State state) (r registration, newState state, err error) {
	newState = State

	// Do an info request to know if registration is required
	i, err := handleInfoWorker(fs)
	if err != nil {
		handleError(err, cViper, false)
		return
	}

	verb := "post"
	log.Printf("Sending `" + action + "` request to autoygg")
	response, err := doRequestWorker(fs, verb, action, gatewayHost, gatewayPort, i)
	if err != nil {
		handleError(err, cViper, false)
		return
	}
	debug("Raw server response:\n\n%s\n\n", string(response))
	err = json.Unmarshal(response, &r)
	handleError(err, cViper, false)
	if err != nil {
		// Only abort when we are not trying to release a lease
		newState.Error = err.Error()
		if cViper.GetString("Action") != "release" {
			saveState(newState)
			return
		}
	}
	if r.Error == "" && action == "register" {
		newState.State = "connected"
		newState.Error = ""
		newState.GatewayHost = gatewayHost
		newState.GatewayPort = gatewayPort
		newState.GatewayPublicKey = r.GatewayPublicKey
		newState.YggdrasilInterface = cViper.GetString("YggdrasilInterface")
		newState.ClientIP = r.ClientIP
		newState.ClientNetMask = r.ClientNetMask
		newState.ClientGateway = r.ClientGateway
		newState.LeaseExpires = r.LeaseExpires
	} else if action == "release" {
		// Errors while releasing can just be ignored from our local state perspective
		newState.State = "disconnected"
	} else if r.Error != "" {
		newState.Error = r.Error
	}
	saveState(newState)
	return
}

func loadState(origState state) (State state, err error) {
	// FIXME add mutex
	State = origState
	path := cViper.GetString("StateDir") + "/client-state.json"
	stateFile, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// no state file, this is often normal, reset err to nil
			debug("State file not found at %s", path)
			err = nil
		}
		return
	}

	err = json.Unmarshal([]byte(stateFile), &State)
	return
}

func saveState(State state) {
	// FIXME add mutex
	debug("Saving client state")
	jsonState, err := json.Marshal(State)
	if err != nil {
		debug(err.Error())
		return
	}

	path := cViper.GetString("StateDir") + "/client-state.json"
	err = os.MkdirAll(cViper.GetString("StateDir"), os.ModePerm)
	if err != nil {
		debug(err.Error())
		return
	}
	err = ioutil.WriteFile(path, jsonState, 0644)
	if err != nil {
		debug(err.Error())
	}
}

func clientValidateConfig() (fs *flag.FlagSet) {
	fs = clientCreateFlagSet(os.Args[1:])

	if cViper.GetBool("UseConfig") {
		cViper.SetConfigType("yaml")
		cViper.SetConfigName("client")
		// Read the configuration from stdin.
		err := cViper.ReadConfig(os.Stdin)
		if err != nil {
			Fatal(err)
		}
	} else if cViper.GetBool("UseUCI") {
		cViper.SetConfigType("yaml")
		cViper.SetConfigName("client")
		// Read the configuration by executing `autoygguci get`. Used on openwrt.
		out, err := command(cViper.GetString("Shell"), cViper.GetString("ShellCommandArg"), "autoygguci get").Output()
		if err != nil {
			Fatal(err)
		}
		err = cViper.ReadConfig(bytes.NewBuffer(out))
		if err != nil {
			Fatal(err)
		}
	} else {
		clientLoadConfig("")
	}

	if cViper.GetBool("Debug") {
		debug = debugLog.Printf
	}

	if cViper.GetBool("State") || cViper.GetString("Action") == "info" {
		// These arguments imply json output
		cViper.Set("Json", true)
	}

	if cViper.GetBool("Help") {
		clientUsage(fs)
		os.Exit(0)
	}

	if cViper.GetBool("Version") {
		fmt.Println(version)
		os.Exit(0)
	}

	if cViper.GetBool("DumpConfig") {
		fmt.Print(dumpConfiguration(cViper, "client"))
		os.Exit(0)
	}

	return
}

func handleInfoWorker(fs *flag.FlagSet) (i info, err error) {
	i, err = doInfoRequest(fs, cViper.GetString("GatewayHost"), cViper.GetString("GatewayPort"))
	if err != nil {
		if os.IsTimeout(err) {
			err = fmt.Errorf("Timeout: could not connect to gateway at %s", cViper.GetString("GatewayHost"))
		}
	}
	return
}

func handleInfo(fs *flag.FlagSet, i info) {
	infoJson, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		logAndExit(err.Error(), 1)
	}
	fmt.Printf("%s\n", infoJson)
	os.Exit(0)
}

// ClientMain is the main() function for the client program
func ClientMain() {
	cViper = viper.New()
	setupLogWriters(cViper, true)

	fs := clientValidateConfig()

	var err error
	var State state
	State, err = loadState(State)
	if err != nil {
		logAndExit(err.Error(), 1)
	}
	State.ClientVersion = version

	if cViper.GetBool("State") {
		json, err := json.MarshalIndent(State, "", "  ")
		if err != nil {
			logAndExit(fmt.Sprintf("Error: %s", err), 1)
		}
		fmt.Printf("%s\n", json)
		os.Exit(0)
	}

	if cViper.GetString("GatewayHost") == "" {
		logAndExit("GatewayHost is not defined", 0)
	}

	if cViper.GetString("Action") == "" {
		logAndExit("Action is not defined", 0)
	}

	if cViper.GetString("Action") == "info" {
		i, err := handleInfoWorker(fs)
		// if the 'info' request failed bail out here
		if err != nil {
			logAndExit(err.Error(), 1)
		}
		handleInfo(fs, i)
	} else {
		if cViper.GetString("Action") == "register" || cViper.GetString("Action") == "renew" {
			State.DesiredState = "connected"
		} else if cViper.GetString("Action") == "release" {
			State.DesiredState = "disconnected"
			State, err = clientTearDownRoutes(State.ClientIP, State.ClientNetMask, State.ClientGateway, State.GatewayPublicKey, State)
			if err != nil {
				Fatal(err)
			}
		}
	}

	b := &backoff.Backoff{
		Min:    100 * time.Millisecond,
		Max:    10 * time.Second,
		Factor: 2,
		Jitter: true,
	}
	var r registration
	for {
		r, State, err = doRequest(fs, cViper.GetString("Action"), cViper.GetString("GatewayHost"), cViper.GetString("GatewayPort"), State)
		if err != nil && cViper.GetBool("Daemon") {
			d := b.Duration()
			time.Sleep(d)
			continue
		} else {
			break
		}
	}

	if r.Error != "" {
		logAndExit(r.Error, 1)
	}
	if err != nil {
		logAndExit(err.Error(), 1)
	}

	if cViper.GetString("Action") == "register" {
		gatewayDev := cViper.GetString("DefaultGatewayDev")
		gatewayIP := cViper.GetString("DefaultGatewayIP")
		if gatewayIP == "" {
			YggdrasilInterface := State.YggdrasilInterface
			if YggdrasilInterface == "" {
				YggdrasilInterface = cViper.GetString("YggdrasilInterface")
			}
			tmpDev, tmpIP, err := DiscoverLocalGateway(YggdrasilInterface)
			if err != nil {
				Fatal(err)
			}
			gatewayIP = tmpIP.String()
			gatewayDev = tmpDev
			debug("Detected gatewayIP %s via gatewayDev %s\n", gatewayIP, gatewayDev)
		}
		State, err = clientSetupRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, gatewayIP, gatewayDev, State)
		if err != nil {
			Fatal(err)
		}
	}

	if cViper.GetBool("Daemon") && cViper.GetString("Action") == "register" {
		log.Printf("Set up cron job to renew lease every 30 minutes")
		c := cron.New()
		_, err := c.AddFunc("CRON_TZ=UTC */30 * * * *", func() {
			State = renewLease(fs, State)
		})
		handleError(err, cViper, false)
		if err != nil {
			Fatal("Couldn't set up cron job!")
		}
		go c.Start()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		fmt.Fprint(os.Stderr, "\r") // Overwrite any ^C that may have been printed on the screen
		State.DesiredState = "disconnected"
		State, _ = clientTearDownRoutes(r.ClientIP, r.ClientNetMask, r.ClientGateway, r.GatewayPublicKey, State)
		_, _, _ = doRequest(fs, "release", cViper.GetString("GatewayHost"), cViper.GetString("GatewayPort"), State)
	}
}
