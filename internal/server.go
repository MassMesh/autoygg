package internal

import (
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // sql driver
	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/zsais/go-gin-prometheus"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	accesslist map[string]acl
)

type acl struct {
	YggIP   string `yaml:"yggip"`
	Access  bool   `yaml:"access"` // True for allowed, false for denied
	Comment string `yaml:"comment"`
}

var errorCount = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "autoygg_error_count",
		Help: "count error by type",
	},
	[]string{"type"},
)

func serverUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `
autoygg-server provides internet egress for Yggdrasil nodes running autoygg-client.

Options:
`)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
}

func incErrorCount(errorType string) {
	if enablePrometheus {
		errorCount.WithLabelValues(errorType).Inc()
	}
}

func enablePrometheusEndpoint() (p *ginprometheus.Prometheus) {
	// Enable basic Prometheus metrics
	p = ginprometheus.NewPrometheus("autoygg")
	return
}

func registrationAllowed(address string) bool {
	if !viper.GetBool("RequireRegistration") {
		// Registration is disabled. Reject.
		debug("Registration is not required, rejecting request from %s\n", address)
		return false
	}

	if viper.GetBool("AccessListEnabled") {
		if _, found := accesslist[address]; found && accesslist[address].Access {
			// The address is on the accesslist. Accept.
			debug("This address is accesslisted, accepted request from %s\n", address)
			return true
		}
	} else {
		// The accesslist is disabled and registration is required. Accept.
		debug("AccessList disabled and registration is required, accepted request from %s\n", address)
		return true
	}
	debug("AccessList enabled and registration is required, address not on accesslist, rejected request from %s\n", address)
	return false
}

func registerHandler(db *gorm.DB, c *gin.Context) {
	var existingRegistration registration
	statusCode := http.StatusOK

	if !validateRegistration(c) {
		return
	}

	if result := db.Where("ygg_ip = ?", c.ClientIP()).First(&existingRegistration); result.Error != nil {
		// IsRecordNotFound is normal if we haven't seen this public key before
		if gorm.IsRecordNotFoundError(result.Error) {
			statusCode = http.StatusNotFound
		} else {
			incErrorCount("internal")
			log.Println("Internal error, unable to execute query:", result.Error)
			c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
			return
		}
	}
	if existingRegistration.State == "pending" {
		statusCode = http.StatusAccepted
	} else if existingRegistration.State == "open" {
		statusCode = http.StatusOK
	} else if existingRegistration.State == "success" {
		statusCode = http.StatusCreated
	} else if existingRegistration.State == "fail" {
		statusCode = http.StatusInternalServerError
	}

	c.JSON(statusCode, existingRegistration)
}

// from https://gist.github.com/udhos/b468fbfd376aa0b655b6b0c539a88c03
func nextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func newIPAddress(db *gorm.DB) (IPAddress string) {
	ipMin := viper.GetString("GatewayTunnelIPRangeMin")
	ipMax := viper.GetString("GatewayTunnelIPRangeMax")

	count := 1
	IP := net.ParseIP(ipMin)
	for count != 0 && IP.String() != ipMax {
		db.Model(&registration{}).Where("client_ip = ?", IP.String()).Count(&count)
		if count != 0 {
			IP = nextIP(IP, 1)
		}
	}
	return IP.String()
}

func bindRegistration(c *gin.Context) (r registration, err error) {
	if e := c.BindJSON(&r); e != nil {
		c.JSON(http.StatusBadRequest, registration{Error: "Malformed json request"})
		c.Abort()
		err = e
		return
	}
	if len(r.PublicKey) != 64 {
		c.JSON(http.StatusBadRequest, registration{Error: "Malformed json request: PublicKey length incorrect"})
		c.Abort()
		err = errors.New("Malformed json request: PublicKey length incorrect")
		r = registration{}
		return
	}
	// FIXME validate that provided public key matches IPv6 address

	return
}

func validateRegistration(c *gin.Context) bool {
	// Is this address allowed to register?
	if !registrationAllowed(c.ClientIP()) {
		c.JSON(http.StatusForbidden, registration{Error: "Registration not allowed"})
		c.Abort()
		incErrorCount("registration_denied")
		return false
	}
	return true
}

func authorized(db *gorm.DB, c *gin.Context) (r registration, existingRegistration registration, err error) {
	r, err = bindRegistration(c)
	if err != nil {
		return
	}
	if !validateRegistration(c) {
		err = errors.New("Registration not allowed")
		return
	}

	if result := db.Where("ygg_ip = ?", c.ClientIP()).First(&existingRegistration); result.Error != nil {
		if gorm.IsRecordNotFoundError(result.Error) {
			c.JSON(http.StatusNotFound, registration{Error: "Registration not found"})
			c.Abort()
			err = result.Error
			return
		}
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		c.Abort()
		err = result.Error
		return
	}
	return
}

func renewHandler(db *gorm.DB, c *gin.Context) {
	registration, existingRegistration, err := authorized(db, c)
	if err != nil {
		return
	}

	registration = existingRegistration

	// FIXME add a mutex here with the timed background thread that is going to cancel leases
	// extend lease
	registration.LeaseExpires = time.Now().UTC().Add(time.Duration(viper.GetInt("LeaseTimeoutSeconds")) * time.Second)

	if registration.State != "success" {
		registration.State = "open"
	}

	if result := db.Save(&registration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

	if registration.State == "open" {
		queueAddRemoteSubnet(db, registration.ID)
	}

	c.JSON(http.StatusOK, registration)
}

func releaseHandler(db *gorm.DB, c *gin.Context) {
	registration, existingRegistration, err := authorized(db, c)
	if err != nil {
		return
	}

	registration = existingRegistration
	// Set the lease expiry date in the past
	registration.LeaseExpires = time.Now().UTC().Add(-10 * time.Second)

	if result := db.Save(&registration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

	// FIXME do not do this inline
	serverRemoveRemoteSubnet(db, registration.ID)

	c.JSON(http.StatusOK, registration)
}

func newRegistrationHandler(db *gorm.DB, c *gin.Context) {
	var newRegistration registration
	if err := c.BindJSON(&newRegistration); err != nil {
		c.JSON(http.StatusBadRequest, registration{Error: "Malformed json request"})
		return
	}
	if len(newRegistration.PublicKey) != 64 {
		c.JSON(http.StatusBadRequest, registration{Error: "Malformed json request: PublicKey length incorrect"})
		return
	}

	if !validateRegistration(c) {
		return
	}

	// Assign a client IP and save it in the database
	// FIXME verify ipv6 <=> public key
	var existingRegistration registration
	if result := db.Where("public_key = ?", newRegistration.PublicKey).First(&existingRegistration); result.Error != nil {
		// IsRecordNotFound is normal if we haven't seen this public key before
		if !gorm.IsRecordNotFoundError(result.Error) {
			incErrorCount("internal")
			log.Println("Internal error, unable to execute query:", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
			return
		}
	}

	if existingRegistration == (registration{}) {
		// First time we've seen this public key
		newRegistration.ClientIP = newIPAddress(db)
		newRegistration.ClientNetMask = viper.GetInt("GatewayTunnelNetMask")
		newRegistration.ClientGateway = viper.GetString("GatewayTunnelIP")
		newRegistration.GatewayPublicKey = viper.GetString("GatewayPublicKey")
		newRegistration.YggIP = c.ClientIP()
	} else {
		// FIXME only allow if the lease is expired?
		// Or simply disallow? But that's annoying.
		newRegistration = existingRegistration
	}
	newRegistration.State = "open"
	// new lease
	newRegistration.LeaseExpires = time.Now().UTC().Add(time.Duration(viper.GetInt("LeaseTimeoutSeconds")) * time.Second)

	if result := db.Save(&newRegistration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
		return
	}
	queueAddRemoteSubnet(db, newRegistration.ID)

	c.JSON(http.StatusOK, newRegistration)
}

func queueAddRemoteSubnet(db *gorm.DB, ID uint) {
	var r registration
	if result := db.First(&r, ID); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return
	}
	if r.State != "open" && r.State != "fail" {
		// Nothing to do!
		return
	}
	// FIXME: actually queue this, rather than doing it inline
	log.Printf("Adding remote subnet for %s", r.ClientIP+"/32")
	err := addRemoteSubnet(r.ClientIP+"/32", r.PublicKey)
	handleError(err, false)

	if err != nil {
		incErrorCount("yggdrasil")
		log.Printf("Yggdrasil error, unable to run command: %s", err)
		r.State = "fail"
	} else {
		r.State = "success"
	}

	if result := db.Save(&r); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return
	}
}

func serverRemoveRemoteSubnet(db *gorm.DB, ID uint) {
	var r registration
	if result := db.First(&r, ID); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return
	}

	// FIXME: actually queue this, rather than doing it inline
	log.Printf("Removing remote subnet for %s", r.ClientIP+"/32")
	err := removeRemoteSubnet(r.ClientIP+"/32", r.PublicKey)
	handleError(err, false)

	if err != nil {
		incErrorCount("yggdrasil")
		log.Printf("%s", err)
		r.State = "fail"
	} else {
		r.State = "removed"
	}

	if result := db.Delete(&r); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return
	}
}

func setupRouter(db *gorm.DB) (r *gin.Engine) {
	gin.SetMode(gin.ReleaseMode)
	r = gin.Default()

	if enablePrometheus {
		p := enablePrometheusEndpoint()
		p.Use(r)
		err := prometheus.Register(errorCount)
		log.Printf("Enabling Prometheus endpoint")
		handleError(err, false)
	}

	noAuth := r.Group("/")
	{
		// 'info' is special, it's the only request does not return a 'registation' struct
		noAuth.GET("/info", func(c *gin.Context) {
			res := info{
				GatewayOwner:        viper.GetString("GatewayOwner"),
				Description:         viper.GetString("GatewayDescription"),
				Network:             viper.GetString("GatewayNetwork"),
				Location:            viper.GetString("GatewayLocation"),
				GatewayInfoURL:      viper.GetString("GatewayInfoURL"),
				RequireRegistration: viper.GetBool("RequireRegistration"),
				RequireApproval:     viper.GetBool("RequireApproval"),
				AccessListEnabled:   viper.GetBool("AccessListEnabled"),
				SoftwareVersion:     version,
			}
			c.JSON(http.StatusOK, res)
		})
		noAuth.GET("/register", func(c *gin.Context) {
			registerHandler(db, c)
		})
		noAuth.POST("/register", func(c *gin.Context) {
			newRegistrationHandler(db, c)
		})
		noAuth.POST("/renew", func(c *gin.Context) {
			renewHandler(db, c)
		})
		noAuth.POST("/release", func(c *gin.Context) {
			releaseHandler(db, c)
		})

	}
	return
}

func setupDB(driver string, credentials string) (db *gorm.DB) {
	db, err := gorm.Open(driver, credentials)
	if err != nil {
		fmt.Printf("%s\n", err)
		Fatal("Couldn't initialize database connection")
	}
	db.LogMode(true)

	// Migrate the schema
	db.AutoMigrate(&registration{})

	return
}

func serverLoadConfigDefaults() {
	viper.SetDefault("ListenHost", "::1")
	viper.SetDefault("ListenPort", "8080")
	viper.SetDefault("GatewayOwner", "Some One <someone@example.com>")
	viper.SetDefault("GatewayDescription", "This is an Yggdrasil internet gateway")
	viper.SetDefault("GatewayNetwork", "Name of the egress network or ISP")
	viper.SetDefault("GatewayLocation", "Physical location of the gateway")
	viper.SetDefault("GatewayInfoURL", "")
	viper.SetDefault("RequireRegistration", true)
	viper.SetDefault("RequireApproval", true)
	viper.SetDefault("MaxClients", 10)
	viper.SetDefault("LeaseTimeoutSeconds", 14400) // Default to 4 hours
	viper.SetDefault("GatewayTunnelIP", "10.42.0.1")
	viper.SetDefault("GatewayTunnelNetMask", 16)
	viper.SetDefault("GatewayTunnelIPRangeMin", "10.42.42.1")   // Minimum IP for "DHCP" range
	viper.SetDefault("GatewayTunnelIPRangeMax", "10.42.42.255") // Maximum IP for "DHCP" range
	viper.SetDefault("AccessListEnabled", true)
	viper.SetDefault("AccessListFile", "accesslist") // Name of the file that contains the accesslist. Omit .yaml extension.
	viper.SetDefault("YggdrasilInterface", "tun0")   // Name of the yggdrasil tunnel interface
	viper.SetDefault("Debug", false)
	viper.SetDefault("Version", false)
	viper.SetDefault("GatewayPublicKey", "")
	// Set up rudimentary firewall rules that will permit
	// * permit forward traffic from the clients
	// * permit forward traffic to the clients
	// * masquerade traffic from the clients
	viper.SetDefault("FirewallWanInterface", "eth0")
	viper.SetDefault("FirewallRuleForwardingOutUp", "iptables -A FORWARD -i %%YggdrasilInterface%% -o %%FirewallWanInterface%% -j ACCEPT")
	viper.SetDefault("FirewallRuleForwardingOutDown", "iptables -D FORWARD -i %%YggdrasilInterface%% -o %%FirewallWanInterface%% -j ACCEPT")
	viper.SetDefault("FirewallRuleForwardingInUp", "iptables -A FORWARD -i %%FirewallWanInterface%% -o %%YggdrasilInterface%% -j ACCEPT")
	viper.SetDefault("FirewallRuleForwardingInDown", "iptables -D FORWARD -i %%FirewallWanInterface%% -o %%YggdrasilInterface%% -j ACCEPT")
	viper.SetDefault("FirewallRuleMasqueradeUp", "iptables -t nat -A POSTROUTING -o %%FirewallWanInterface%% -j MASQUERADE")
	viper.SetDefault("FirewallRuleMasqueradeDown", "iptables -t nat -D POSTROUTING -o %%FirewallWanInterface%% -j MASQUERADE")
}

func serverLoadConfig(path string) (fs *flag.FlagSet) {
	viperLoadSharedDefaults()
	serverLoadConfigDefaults()

	viper.SetEnvPrefix("AUTOYGG") // will be uppercased automatically
	err := viper.BindEnv("CONFIG")
	if err != nil {
		Fatal(fmt.Sprintln("Fatal error:", err.Error()))
	}

	config := "server"
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
	configErr := viper.ReadInConfig()

	// First handle command line flags, some of which should not depend on the presence of
	// a config file
	fs = flag.NewFlagSet("Autoygg", flag.ContinueOnError)
	fs.Usage = func() { serverUsage(fs) }
	fs.Bool("dumpConfig", false, "dump the configuration that would be used by autoygg-server and exit")
	fs.Bool("help", false, "print usage and exit")
	fs.Bool("version", false, "print version and exit")

	err = fs.Parse(os.Args[1:])
	if err != nil {
		Fatal(err)
	}

	err = viper.BindPFlags(fs)
	if err != nil {
		Fatal(err)
	}

	if viper.GetBool("Help") {
		serverUsage(fs)
		os.Exit(0)
	}

	if viper.GetBool("Version") {
		fmt.Println(version)
		os.Exit(0)
	}

	if viper.GetBool("Debug") {
		debug = debugLog.Printf
	}

	if configErr != nil {
		Fatal(fmt.Sprintln("Fatal error reading config file:", err.Error()))
	}

	initializeViperList("AccessList", path, &accesslist)

	viper.WatchConfig() // Automatically reload the main config when it changes
	viper.OnConfigChange(func(e fsnotify.Event) {
		if viper.GetBool("Debug") {
			debug = debugLog.Printf
		} else {
			debug = func(string, ...interface{}) {}
		}
		fmt.Println("Config file changed:", e.Name)
	})

	return
}

func initializeViperList(name string, path string, list *map[string]acl) {
	if viper.GetBool(name + "Enabled") {
		// Viper only supports watching one config file at the moment (cf issue #631)
		// Set up an additional viper for this list
		localViper := viper.New()
		localViper.SetConfigType("yaml")
		localViper.SetConfigName(viper.GetString(name + "File"))
		localViper.AddConfigPath(path)
		localViper.AddConfigPath("/etc/autoygg/")
		localViper.AddConfigPath("$HOME/.autoygg")
		localViper.AddConfigPath(".")

		err := localViper.ReadInConfig()
		if err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				fmt.Printf("Warning: config file `%s.yaml` not found\n", viper.GetString(name+"File"))
				err = nil
			} else {
				Fatal(fmt.Sprintf("while reading config file `%s.yaml`: %s\n", viper.GetString(name+"File"), err.Error()))
			}
		} else {
			*list = loadList(name, localViper)
			localViper.WatchConfig() // Automatically reload the config files when they change
			localViper.OnConfigChange(func(e fsnotify.Event) {
				fmt.Println("Config file changed:", e.Name)
				*list = loadList(name, localViper)
			})
		}
	}
}

// convert the accesslist viper slices into a map for cheap lookup
func loadList(name string, localViper *viper.Viper) map[string]acl {
	list := make(map[string]acl)
	var slice []acl
	if !viper.GetBool(name + "Enabled") {
		fmt.Printf("%sEnabled is not set", name)
		return list
	}
	err := localViper.UnmarshalKey("accesslist", &slice)
	if err != nil {
		Fatal(fmt.Sprintf("while reading config file `%s.yaml`: %s\n", viper.GetString(name+"File"), err.Error()))
	}
	for _, v := range slice {
		if ValidYggdrasilAddress(v.YggIP) {
			list[v.YggIP] = v
			debug("Parsed acl %+v for Yggdrasil IP %s\n", v, v.YggIP)
		} else {
			fmt.Printf("Warning: %s: skipping acl %+v with invalid Yggdrasil IP %s\n", name, v, v.YggIP)
		}
	}

	return list
}

// ValidYggdrasilAddress tests if an address is a valid Yggdrasil IPv6 address
// in the 200::/7 block
func ValidYggdrasilAddress(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil {
		// address is not parsable as an IP address
		return false
	}
	if ip.To4() != nil {
		// address is an IPv4 address
		return false
	}
	_, IPNet, err := net.ParseCIDR("200::/7")
	if err != nil {
		// Something went wrong parsing the Yggdrasil subnet CIDR
		return false
	}
	if !IPNet.Contains(ip) {
		// address is not in the Yggdrasil subnet
		return false
	}
	return true
}

func disableIPForwarding() error {
	return ipForwardingWorker("0")
}

func enableIPForwarding() error {
	return ipForwardingWorker("1")
}

func ipForwardingWorker(payload string) (err error) {
	f, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward", os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	b := make([]byte, 1)
	_, err = f.Read(b)
	if err != nil {
		fmt.Println(err)
		return
	}
	ipForward := string(b)
	if ipForward != payload {
		_, err = f.Seek(0, 0)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, err = f.WriteString(payload)
		if err != nil {
			fmt.Println(err)
			return
		}
		if payload == "1" {
			configChanges = append(configChanges, configChange{Name: "IPForwarding", OldVal: ipForward, NewVal: payload})
		}
	}
	return
}

func firewallRulesWorker(action string, rule string) (err error) {
	cmd := viper.GetString(rule + action)
	cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", viper.GetString("YggdrasilInterface"), -1)
	cmd = strings.Replace(cmd, "%%FirewallWanInterface%%", viper.GetString("FirewallWanInterface"), -1)

	out, err := command(viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s (%s)", viper.GetString("Shell"), viper.GetString("ShellCommandArg"), cmd, err, out)
		return
	}
	if action == "Up" {
		configChanges = append(configChanges, configChange{Name: rule, OldVal: "", NewVal: ""})
	}
	return
}

type configChange struct {
	Name   string
	OldVal interface{}
	NewVal interface{}
}

var configChanges []configChange

func setup() {
	log.Printf("Set up firewall rule Forwarding Out")
	err := firewallRulesWorker("Up", "FirewallRuleForwardingOut")
	handleError(err, false)
	log.Printf("Set up firewall rule Forwarding In")
	err = firewallRulesWorker("Up", "FirewallRuleForwardingIn")
	handleError(err, false)
	log.Printf("Set up firewall rule Masquerading")
	err = firewallRulesWorker("Up", "FirewallRuleMasquerade")
	handleError(err, false)
	log.Printf("Enabling IP forwarding")
	err = enableIPForwarding()
	handleError(err, true)
	log.Printf("Enabling Yggdrasil tunnel routing")
	err = enableTunnelRouting()
	handleError(err, true)
	log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
	err = addLocalSubnet("0.0.0.0/0")
	handleError(err, true)
	log.Printf("Adding tunnel IP %s/%d", viper.GetString("GatewayTunnelIP"), viper.GetInt("GatewayTunnelNetmask"))
	err = addTunnelIP(viper.GetString("GatewayTunnelIP"), viper.GetInt("GatewayTunnelNetmask"))
	handleError(err, true)
}

func tearDown() {
	for i := len(configChanges) - 1; i >= 0; i-- {
		change := configChanges[i]
		debug("Tearing down %+v\n", change)
		if change.Name == "TunnelIP" {
			log.Printf("Removing tunnel IP %s/%d", viper.GetString("GatewayTunnelIP"), viper.GetInt("GatewayTunnelNetmask"))
			err := removeTunnelIP(viper.GetString("GatewayTunnelIP"), viper.GetInt("GatewayTunnelNetmask"))
			handleError(err, true)
		} else if change.Name == "LocalSubnet" {
			log.Printf("Removing Yggdrasil local subnet 0.0.0.0/0")
			err := removeLocalSubnet("0.0.0.0/0")
			handleError(err, true)
		} else if change.Name == "TunnelRouting" {
			log.Printf("Disabling Yggdrasil tunnel routing")
			err := disableTunnelRouting()
			handleError(err, true)
		} else if change.Name == "IPForwarding" {
			log.Printf("Disabling IP forwarding")
			err := disableIPForwarding()
			handleError(err, true)
		} else if change.Name == "FirewallRuleForwardingOut" {
			log.Printf("Disabling FirewallRuleForwardingOut")
			err := firewallRulesWorker("Down", "FirewallRuleForwardingOut")
			handleError(err, true)
		} else if change.Name == "FirewallRuleForwardingIn" {
			log.Printf("Disabling FirewallRuleForwardingIn")
			err := firewallRulesWorker("Down", "FirewallRuleForwardingIn")
			handleError(err, true)
		} else if change.Name == "FirewallRuleMasquerade" {
			log.Printf("Disabling FirewallRuleMasquerade")
			err := firewallRulesWorker("Down", "FirewallRuleMasquerade")
			handleError(err, true)
		}
	}
}

// ServerMain is the main() function for the server program
func ServerMain() {
	setupLogWriters()

	// Enable the Prometheus endpoint
	enablePrometheus = true

	fs := serverLoadConfig("")

	// if GatewayPublicKey is not set in the config, calculate it here.
	// This has the advantage that --help and --version are already handled
	// at this point, so these calls won't error out if yggdrasil is not
	// installed or the user doesn't have enough permissions to talk to it.
	if viper.GetString("GatewayPublicKey") == "" {
		gatewayPublicKey, err := getSelfPublicKey()
		if err != nil {
			incErrorCount("yggdrasil")
			fmt.Printf("Error: unable to run yggdrasilctl: %s\n", err)
			os.Exit(1)
		} else {
			viper.Set("GatewayPublicKey", gatewayPublicKey)
		}
	}

	if viper.GetBool("DumpConfig") {
		fmt.Print(dumpConfiguration("server"))
		os.Exit(0)
	}
	debug(dumpConfiguration("server"))

	if viper.GetString("StateDir") == "" {
		fmt.Println("Error: StateDir must not be empty. Please check the configuration file.")
		serverUsage(fs)
		os.Exit(1)
	}

	if _, err := os.Stat(viper.GetString("StateDir")); os.IsNotExist(err) {
		err = os.MkdirAll(viper.GetString("StateDir"), os.FileMode(0700))
		if err != nil {
			Fatal(err)
		}
	}

	db := setupDB("sqlite3", viper.GetString("StateDir")+"/autoygg.db")
	defer db.Close()
	r := setupRouter(db)

	setup()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		err := r.Run("[" + viper.GetString("ListenHost") + "]:" + viper.GetString("ListenPort"))
		if err != nil {
			log.Print("Starting autoygg server daemon")
			handleError(err, false)
		}
	}()
	<-sig
	fmt.Print("\r") // Overwrite any ^C that may have been printed on the screen
	tearDown()
}
