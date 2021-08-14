package internal

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // sql driver
	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/zsais/go-gin-prometheus"
)

var (
	accesslist map[string]acl
	mutex      sync.Mutex
	sViper     *viper.Viper
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

var validLeases = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "autoygg_valid_leases_total",
		Help: "Number of valid leases.",
	})

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

func countValidLeases(db *gorm.DB) error {
	if enablePrometheus {
		var registrations []registration
		result := db.Model(&registration{}).Where("state = 'success' and lease_expires > ?", time.Now()).Find(&registrations)
		if result.Error != nil {
			err := result.Error
			return err
		}
		debug("Found %d valid leases\n", result.RowsAffected)
		validLeases.Set(float64(result.RowsAffected))
	}
	return nil
}

func enablePrometheusEndpoint() (p *ginprometheus.Prometheus) {
	// Enable basic Prometheus metrics
	p = ginprometheus.NewPrometheus("autoygg")
	return
}

func checkACL(address string) bool {
	if sViper.GetBool("AccessListEnabled") {
		if _, found := accesslist[address]; found && accesslist[address].Access {
			// The address is on the accesslist. Accept.
			log.Printf("This address is accesslisted, accepted request from %s\n", address)
			return true
		}
		log.Printf("AccessList enabled and this address is not on the access list, rejected request from %s\n", address)
		return false
	}
	// The accesslist is disabled. Accept.
	log.Println("AccessList disabled, accepted request from", address)
	return true
}

func registerHandler(db *gorm.DB, c *gin.Context) {
	var existingRegistration registration
	statusCode := http.StatusOK

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

	if !validateRegistration(c, existingRegistration) {
		return
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

func newIPAddress(db *gorm.DB) (string, string) {
	ipMin := sViper.GetString("GatewayTunnelIPRangeMin")
	ipMax := sViper.GetString("GatewayTunnelIPRangeMax")

	count := 0
	IP := net.ParseIP(ipMin)
	tunnelName := ""
	clientCount := 0
	for IP.String() != ipMax {
		db.Model(&registration{}).Where("client_ip = ?", IP.String()).Count(&count)
		if count != 0 {
			IP = nextIP(IP, 1)
			clientCount++
		} else {
			tunnelName = "autoygg_client" + strconv.Itoa(clientCount)
			break
		}
	}
	debug("New IP %+v (%+v)\n", IP.String(), tunnelName)
	return IP.String(), tunnelName
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

func validateRegistration(c *gin.Context, r registration) bool {
	// Is this address allowed to register?
	if !checkACL(c.ClientIP()) {
		c.JSON(http.StatusForbidden, registration{Error: "Registration not allowed"})
		c.Abort()
		incErrorCount("registration_denied_acl")
		return false
	}
	// When RequireRegistration is set, make sure there are values in Name/Phone/E-mail
	if sViper.GetBool("RequireRegistration") {
		if r.ClientEmail == "" ||
			r.ClientPhone == "" ||
			r.ClientName == "" {
			c.JSON(http.StatusForbidden, registration{Error: "Client name, e-mail and phone must be supplied"})
			c.Abort()
			incErrorCount("registration_denied_missing_client_info")
			return false
		}
	}
	return true
}

func authorized(db *gorm.DB, c *gin.Context) (r registration, existingRegistration registration, err error) {
	r, err = bindRegistration(c)
	if err != nil {
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
		// authorized terminates the http request properly
		return
	}

	registration = existingRegistration
	registration.LeaseExpires = time.Now().UTC().Add(time.Duration(sViper.GetInt("LeaseTimeoutSeconds")) * time.Second)

	if registration.State == "expired" {
		c.JSON(http.StatusNotFound, gin.H{"Error": "Registration not found"})
		return
	}

	if registration.State != "success" {
		registration.State = "open"
	}

	mutex.Lock()
	defer mutex.Unlock()
	if result := db.Save(&registration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

	if registration.State == "open" {
		err = queueAddTunnel(db, registration.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"{Error": "Internal Server Error"})
			return
		}
	}

	c.JSON(http.StatusOK, registration)
}

func releaseHandler(db *gorm.DB, c *gin.Context) {
	registration, existingRegistration, err := authorized(db, c)
	if err != nil {
		// authorized terminates the http request properly
		return
	}

	registration = existingRegistration
	if registration.State == "expired" {
		c.JSON(http.StatusNotFound, gin.H{"Error": "Registration not found"})
		return
	}

	// Set the lease expiry date in the past
	registration.LeaseExpires = time.Now().UTC().Add(-10 * time.Second)
	registration.State = "expired"

	mutex.Lock()
	defer mutex.Unlock()
	if result := db.Save(&registration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

	// FIXME do not do this inline
	err = removeClientTunnel(sViper, registration.ClientTunnelName)
	if err != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to remove client tunnel", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

	err = countValidLeases(db)
	if err != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to count valid leases", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
		return
	}

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

	if !validateRegistration(c, newRegistration) {
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
		newRegistration.ClientIP, newRegistration.ClientTunnelName = newIPAddress(db)
		newRegistration.ClientNetMask = sViper.GetInt("GatewayTunnelNetMask")
		newRegistration.ClientGateway = sViper.GetString("GatewayTunnelIP")
		newRegistration.GatewayPublicKey = sViper.GetString("GatewayPublicKey")
		newRegistration.YggIP = c.ClientIP()
		if newRegistration.ClientTunnelName == "" {
			incErrorCount("internal")
			log.Println("Internal error, ClientTunnelName unset")
			c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
			return
		}
	} else {
		// FIXME only allow if the lease is expired?
		// Or simply disallow? But that's annoying.
		newRegistration = existingRegistration
	}
	newRegistration.State = "open"
	// new lease
	newRegistration.LeaseExpires = time.Now().UTC().Add(time.Duration(sViper.GetInt("LeaseTimeoutSeconds")) * time.Second)

	debug("New registration: %+v\n", newRegistration)
	mutex.Lock()
	defer mutex.Unlock()
	if result := db.Save(&newRegistration); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
		return
	}
	err := queueAddTunnel(db, newRegistration.ID)
	if err != nil {
		incErrorCount("internal")
		c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
		return
	}
	err = countValidLeases(db)
	if err != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to count valid leases", err)
		c.JSON(http.StatusInternalServerError, registration{Error: "Internal Server Error"})
		return
	}

	c.JSON(http.StatusOK, newRegistration)
}

// caller must hold the mutex lock
func queueAddTunnel(db *gorm.DB, ID uint) error {
	var r registration
	if result := db.First(&r, ID); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return result.Error
	}
	if r.State != "open" && r.State != "fail" {
		// Nothing to do!
		return nil
	}
	// FIXME: actually queue this, rather than doing it inline
	log.Printf("Add tunnel %s for %s", r.ClientTunnelName, r.ClientIP+"/32")
	err := addClientTunnel(sViper, r.ClientTunnelName, "", r.ClientIP, 32, r.YggIP)
	handleError(err, sViper, false)

	if err != nil {
		incErrorCount("internal")
		r.State = "fail"
	} else {
		r.State = "success"
	}

	if result := db.Save(&r); result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		return result.Error
	}

	if r.State != "success" {
		return err
	}
	return nil
}

func setupRouter(db *gorm.DB) (r *gin.Engine) {
	gin.SetMode(gin.ReleaseMode)
	r = gin.Default()

	if enablePrometheus {
		p := enablePrometheusEndpoint()
		p.Use(r)
		log.Printf("Enabling Prometheus endpoint")
		err := prometheus.Register(errorCount)
		handleError(err, sViper, false)
		err = prometheus.Register(validLeases)
		handleError(err, sViper, false)
	}

	noAuth := r.Group("/")
	{
		// 'info' is special, it's the only request does not return a 'registation' struct
		noAuth.GET("/info", func(c *gin.Context) {
			res := info{
				GatewayOwner:        sViper.GetString("GatewayOwner"),
				Description:         sViper.GetString("GatewayDescription"),
				Network:             sViper.GetString("GatewayNetwork"),
				Location:            sViper.GetString("GatewayLocation"),
				GatewayInfoURL:      sViper.GetString("GatewayInfoURL"),
				RequireRegistration: sViper.GetBool("RequireRegistration"),
				AccessListEnabled:   sViper.GetBool("AccessListEnabled"),
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

func setupDB(driver string, credentials string, databaseDebug bool) (db *gorm.DB) {
	db, err := gorm.Open(driver, credentials)
	if err != nil {
		fmt.Printf("%s\n", err)
		Fatal("Couldn't initialize database connection")
	}
	if databaseDebug {
		db.LogMode(true)
	}

	// Migrate the schema
	db.AutoMigrate(&registration{})

	return
}

func serverLoadConfigDefaults() {
	sViper.SetDefault("ListenHost", "::1")
	sViper.SetDefault("ListenPort", "8080")
	sViper.SetDefault("GatewayOwner", "Some One <someone@example.com>")
	sViper.SetDefault("GatewayDescription", "This is an Yggdrasil internet gateway")
	sViper.SetDefault("GatewayNetwork", "Name of the egress network or ISP")
	sViper.SetDefault("GatewayLocation", "Physical location of the gateway")
	sViper.SetDefault("GatewayInfoURL", "")
	sViper.SetDefault("RequireRegistration", true)
	sViper.SetDefault("MaxClients", 10)
	sViper.SetDefault("LeaseTimeoutSeconds", 14400) // Default to 4 hours
	sViper.SetDefault("GatewayTunnelIP", "10.42.0.1")
	sViper.SetDefault("GatewayTunnelNetMask", 16)
	sViper.SetDefault("GatewayTunnelIPRangeMin", "10.42.42.1")   // Minimum IP for "DHCP" range
	sViper.SetDefault("GatewayTunnelIPRangeMax", "10.42.42.255") // Maximum IP for "DHCP" range
	sViper.SetDefault("AccessListEnabled", true)
	sViper.SetDefault("AccessListFile", "accesslist") // Name of the file that contains the accesslist. Omit .yaml extension.
	sViper.SetDefault("YggdrasilInterface", "tun0")   // Name of the yggdrasil tunnel interface
	sViper.SetDefault("Debug", false)
	sViper.SetDefault("DatabaseDebug", false)
	sViper.SetDefault("Version", false)
	sViper.SetDefault("GatewayPublicKey", "")
	// Set up rudimentary firewall rules that will permit
	// * permit forward traffic from the clients
	// * permit forward traffic to the clients
	// * masquerade traffic from the clients
	sViper.SetDefault("GatewayWanInterface", "eth0")
	sViper.SetDefault("AddFirewallRuleForwardingOutCommand", "iptables -A FORWARD -i %%YggdrasilInterface%% -o %%GatewayWanInterface%% -j ACCEPT")
	sViper.SetDefault("DelFirewallRuleForwardingOutCommand", "iptables -D FORWARD -i %%YggdrasilInterface%% -o %%GatewayWanInterface%% -j ACCEPT")
	sViper.SetDefault("AddFirewallRuleForwardingInCommand", "iptables -A FORWARD -i %%GatewayWanInterface%% -o %%YggdrasilInterface%% -j ACCEPT")
	sViper.SetDefault("DelFirewallRuleForwardingInCommand", "iptables -D FORWARD -i %%GatewayWanInterface%% -o %%YggdrasilInterface%% -j ACCEPT")
	sViper.SetDefault("AddFirewallRuleMasqueradeCommand", "iptables -t nat -A POSTROUTING -o %%GatewayWanInterface%% -j MASQUERADE")
	sViper.SetDefault("DelFirewallRuleMasqueradeCommand", "iptables -t nat -D POSTROUTING -o %%GatewayWanInterface%% -j MASQUERADE")
	// routing table number. All routes will be installed in this table, and a rule will be added to direct traffic
	// from the mesh to it.
	sViper.SetDefault("RoutingTableNumber", 42)
	sViper.SetDefault("ListIpRuleCommand", "ip rule list |grep 'from %%GatewayTunnelIP%%/%%GatewayTunnelNetMask%% lookup %%RoutingTableNumber%%'")
	sViper.SetDefault("AddIpRuleCommand", "ip rule add from %%GatewayTunnelIP%%/%%GatewayTunnelNetMask%% table %%RoutingTableNumber%%")
	sViper.SetDefault("DelIpRuleCommand", "ip rule del from %%GatewayTunnelIP%%/%%GatewayTunnelNetMask%% table %%RoutingTableNumber%%")
	sViper.SetDefault("ListIpRouteTableMeshCommand", "ip ro list default dev %%GatewayWanInterface%% table %%RoutingTableNumber%%")
	sViper.SetDefault("AddIpRouteTableMeshCommand", "ip ro add default dev %%GatewayWanInterface%% table %%RoutingTableNumber%%")
	sViper.SetDefault("DelIpRouteTableMeshCommand", "ip ro del default dev %%GatewayWanInterface%% table %%RoutingTableNumber%%")
}

func serverLoadConfig(path string, args []string) (fs *flag.FlagSet) {
	viperLoadSharedDefaults(sViper)
	serverLoadConfigDefaults()

	sViper.SetEnvPrefix("AUTOYGG") // will be uppercased automatically
	err := sViper.BindEnv("CONFIG")
	if err != nil {
		Fatal(fmt.Sprintln("Fatal error:", err.Error()))
	}

	config := "server"
	if sViper.Get("CONFIG") != nil {
		config = sViper.Get("CONFIG").(string)
	}

	// Load the main config file
	sViper.SetConfigType("yaml")
	sViper.SetConfigName(config)
	if path == "" {
		sViper.AddConfigPath("/etc/autoygg/")
		sViper.AddConfigPath("$HOME/.autoygg")
		sViper.AddConfigPath(".")
	} else {
		// For testing
		sViper.AddConfigPath(path)
	}
	configErr := sViper.ReadInConfig()

	// First handle command line flags, some of which should not depend on the presence of
	// a config file
	fs = flag.NewFlagSet("Autoygg", flag.ContinueOnError)
	fs.Usage = func() { serverUsage(fs) }
	fs.Bool("dumpConfig", false, "dump the configuration that would be used by autoygg-server and exit")
	fs.Bool("help", false, "print usage and exit")
	fs.Bool("version", false, "print version and exit")

	err = fs.Parse(args)
	if err != nil {
		Fatal(err)
	}

	err = sViper.BindPFlags(fs)
	if err != nil {
		Fatal(err)
	}

	if sViper.GetBool("Help") {
		serverUsage(fs)
		os.Exit(0)
	}

	if sViper.GetBool("Version") {
		fmt.Println(version)
		os.Exit(0)
	}

	if sViper.GetBool("Debug") {
		debug = debugLog.Printf
	}

	if configErr != nil {
		Fatal(fmt.Sprintln("Fatal error reading config file:", configErr.Error()))
	}

	initializeViperList("AccessList", path, &accesslist)

	sViper.OnConfigChange(func(e fsnotify.Event) {
		if sViper.GetBool("Debug") {
			debug = debugLog.Printf
		} else {
			debug = func(string, ...interface{}) {}
		}
		log.Println("Config file changed:", e.Name)
		debug("Current configuration:")
		debug("+=+=+=+=+=+=+=+=+=+=+=")
		debug(dumpConfiguration(sViper, "server"))
		debug("+=+=+=+=+=+=+=+=+=+=+=")
	})
	sViper.WatchConfig() // Automatically reload the main config when it changes

	return
}

func initializeViperList(name string, path string, list *map[string]acl) {
	if sViper.GetBool(name + "Enabled") {
		// Viper only supports watching one config file at the moment (cf issue #631)
		// Set up an additional viper for this list
		localViper := viper.New()
		localViper.SetConfigType("yaml")
		localViper.SetConfigName(sViper.GetString(name + "File"))
		localViper.AddConfigPath(path)
		localViper.AddConfigPath("/etc/autoygg/")
		localViper.AddConfigPath("$HOME/.autoygg")
		localViper.AddConfigPath(".")

		err := localViper.ReadInConfig()
		if err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				fmt.Printf("Warning: config file `%s.yaml` not found\n", sViper.GetString(name+"File"))
				err = nil
			} else {
				Fatal(fmt.Sprintf("while reading config file `%s.yaml`: %s\n", sViper.GetString(name+"File"), err.Error()))
			}
		} else {
			*list = loadList(name, localViper)
			localViper.WatchConfig() // Automatically reload the config files when they change
			localViper.OnConfigChange(func(e fsnotify.Event) {
				// It would be nice to dump the config here
				log.Println(name+" file changed:", e.Name)
				// If the configuration file that is reloaded is an access list, the localViper config object is empty
				if name == "Config" {
					debug("New configuration:")
					debug("+=+=+=+=+=+=+=+=+=+=+=")
					debug(dumpConfiguration(localViper, "server"))
					debug("+=+=+=+=+=+=+=+=+=+=+=")
				}
				*list = loadList(name, localViper)
			})
		}
	}
}

// convert the accesslist viper slices into a map for cheap lookup
func loadList(name string, localViper *viper.Viper) map[string]acl {
	list := make(map[string]acl)
	var slice []acl
	if !sViper.GetBool(name + "Enabled") {
		fmt.Printf("%sEnabled is not set\n", name)
		return list
	}
	err := localViper.UnmarshalKey("accesslist", &slice)
	if err != nil {
		Fatal(fmt.Sprintf("while reading config file `%s.yaml`: %s\n", sViper.GetString(name+"File"), err.Error()))
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

func firewallRulesWorker(action string, commandName string) (err error) {
	cmd := sViper.GetString(action + commandName)
	cmd = strings.Replace(cmd, "%%YggdrasilInterface%%", sViper.GetString("YggdrasilInterface"), -1)
	cmd = strings.Replace(cmd, "%%GatewayWanInterface%%", sViper.GetString("GatewayWanInterface"), -1)

	out, err := command(sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s (%s)", sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd, err, out)
		return
	}
	if action == "Add" {
		configChanges = append(configChanges, configChange{Name: commandName, OldVal: "", NewVal: ""})
	}
	return
}

func commandWorker(action string, commandName string, substitutes []string, ignoreListError bool) (err error) {
	cmd := sViper.GetString("List" + commandName)
	for _, sub := range substitutes {
		cmd = strings.Replace(cmd, "%%"+sub+"%%", sViper.GetString(sub), -1)
	}

	out, err := command(sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd).Output()
	// if ignoreListError is true, a failed list command is the equivalent of a list command without output
	if !ignoreListError && err != nil {
		err = fmt.Errorf("Unable to run `%s %s %s`: %s", sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd, err)
		return
	}

	if (action == "Add" && len(out) == 0) || (action == "Del" && len(out) != 0) {
		cmd = sViper.GetString(action + commandName)
		for _, sub := range substitutes {
			cmd = strings.Replace(cmd, "%%"+sub+"%%", sViper.GetString(sub), -1)
		}
		out, err = command(sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("Unable to run `%s %s %s`: %s (%s)", sViper.GetString("Shell"), sViper.GetString("ShellCommandArg"), cmd, err, out)
			return
		}
	} else {
		debug("Command output for action %s: %s (len %d)\n", action, string(out), len(out))
	}
	if action == "Add" {
		configChanges = append(configChanges, configChange{Name: commandName, OldVal: "", NewVal: ""})
	}
	return
}

// ipRouteMeshTableWorker installs a default route in the mesh routing table
// (defaults to id 42), but only if the host default gateway is different from
// GatewayWanInterface. This is the case in a vpn scenario, where
// GatewayWanInterface will be configured to (e.g.) `vpn0`, which is a
// point-to-point link to the vpn server. In that case, the mesh routing table
// should have a default route to send all traffic out over that interface.
//
// In the non-vpn case, all traffic from the
// GatewayTunnelIP/GatewayTunnelNetmask network will still go via the mesh
// routing table, but we don't install any routes into it, so the traffic will
// then continue to be routed by the main table.
func ipRouteMeshTableWorker(action string, message string) (err error) {
	dev, _, err := DiscoverLocalGateway(sViper.GetString("YggdrasilInterface"))
	if err != nil {
		return
	}
	debug("Detected gateway device is %s, while configured GatewayWanInterface is %s", dev, sViper.GetString("GatewayWanInterface"))
	if dev != sViper.GetString("GatewayWanInterface") {
		log.Print(message)
		err = commandWorker(action, "IpRouteTableMeshCommand", []string{"GatewayWanInterface", "RoutingTableNumber"}, true)
	}

	return
}

type configChange struct {
	Name   string
	OldVal interface{}
	NewVal interface{}
}

var configChanges []configChange

// loadLeases loads the valid leases from the database and makes sure that
// Yggdrasil has the correct remote subnets configured. loadLeases is called
// when autoygg-server starts up.  It is not strictly necessary when
// autoygg-server is restarted, but it is required when Yggdrasil is restarted,
// e.g. after a reboot of the machine.
func loadLeases(db *gorm.DB) (err error) {
	var registrations []registration

	result := db.Model(&registration{}).Where("state = 'success' and lease_expires > ?", time.Now()).Find(&registrations)
	if result.Error != nil {
		err = result.Error
		return
	}
	debug("Found %d valid leases to load\n", result.RowsAffected)

	// These leases are still valid, make sure everything is configured properly
	mutex.Lock()
	defer mutex.Unlock()
	for _, r := range registrations {
		r.State = "open"
		if result := db.Save(&r); result.Error != nil {
			incErrorCount("internal")
			log.Println("Internal error, unable to execute query:", result.Error)
			return
		}
		debug("re-enabling lease for registration %+v\n", r)
		err = queueAddTunnel(db, r.ID)
		if err != nil {
			incErrorCount("internal")
			return
		}
	}

	return
}

func setup() {
	log.Printf("Set up firewall rule Forwarding Out")
	err := firewallRulesWorker("Add", "FirewallRuleForwardingOutCommand")
	handleError(err, sViper, false)
	log.Printf("Set up firewall rule Forwarding In")
	err = firewallRulesWorker("Add", "FirewallRuleForwardingInCommand")
	handleError(err, sViper, false)
	log.Printf("Set up firewall rule Masquerading")
	err = firewallRulesWorker("Add", "FirewallRuleMasqueradeCommand")
	handleError(err, sViper, false)
	log.Printf("Enabling IP forwarding")
	err = enableIPForwarding()
	handleError(err, sViper, true)
	log.Printf("Add ip rule for %s/%d to table %d", sViper.GetString("GatewayTunnelIP"), sViper.GetInt("GatewayTunnelNetmask"), sViper.GetInt("RoutingTableNumber"))
	err = commandWorker("Add", "IpRuleCommand", []string{"GatewayTunnelIP", "GatewayTunnelNetMask", "RoutingTableNumber"}, true)
	handleError(err, sViper, true)
	err = ipRouteMeshTableWorker("Add", fmt.Sprintf("Detected vpn configuration, adding mesh routing default gateway to table %d", sViper.GetInt("RoutingTableNumber")))
	handleError(err, sViper, true)
}

func tearDown() {
	for i := len(configChanges) - 1; i >= 0; i-- {
		change := configChanges[i]
		debug("Tearing down %+v\n", change)
		if change.Name == "IpRuleCommand" {
			log.Printf("Removing ip rule for %s/%d to table %d", sViper.GetString("GatewayTunnelIP"), sViper.GetInt("GatewayTunnelNetmask"), sViper.GetInt("RoutingTableNumber"))
			err := commandWorker("Del", "IpRuleCommand", []string{"GatewayTunnelIP", "GatewayTunnelNetMask", "RoutingTableNumber"}, true)
			handleError(err, sViper, true)
		} else if change.Name == "IpRouteTableMeshCommand" {
			log.Printf("Removing mesh routing default gateway from table %d", sViper.GetInt("RoutingTableNumber"))
			err := commandWorker("Del", "IpRouteTableMeshCommand", []string{"GatewayWanInterface", "RoutingTableNumber"}, false)
			handleError(err, sViper, true)
		} else if change.Name == "IPForwarding" {
			log.Printf("Disabling IP forwarding")
			err := disableIPForwarding()
			handleError(err, sViper, true)
		} else if change.Name == "FirewallRuleForwardingOutCommand" {
			log.Printf("Disabling FirewallRuleForwardingOut")
			err := firewallRulesWorker("Del", change.Name)
			handleError(err, sViper, true)
		} else if change.Name == "FirewallRuleForwardingInCommand" {
			log.Printf("Disabling FirewallRuleForwardingIn")
			err := firewallRulesWorker("Del", change.Name)
			handleError(err, sViper, true)
		} else if change.Name == "FirewallRuleMasqueradeCommand" {
			log.Printf("Disabling FirewallRuleMasquerade")
			err := firewallRulesWorker("Del", change.Name)
			handleError(err, sViper, true)
		}
	}
}

// expireLeases runs in the background and makes sure to remove Yggdrasil's
// remote subnet for expired leases.
func expireLeases(db *gorm.DB, mutex *sync.Mutex) {
	ticker := time.NewTicker(5 * time.Second)
	for t := range ticker.C {
		debug("Wakeup at %s\n", t.Format("2006-01-02 15:04:05"))
		expireLeasesWorker(db, mutex)
	}
}

// expireLeasesWorker is a separate function to facilitate testing
func expireLeasesWorker(db *gorm.DB, mutex *sync.Mutex) {
	mutex.Lock()
	var registrations []registration
	// FIXME this uses a sqlite-ism for the timestamp comparison
	result := db.Model(&registration{}).Where("state = 'success' and datetime(lease_expires) <= datetime('now')").Find(&registrations)
	if result.Error != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to execute query:", result.Error)
		mutex.Unlock()
		return
	}
	debug("Found %d leases to expire\n", result.RowsAffected)

	// These leases are expired, mark them as such and make sure that Yggdrasil doesn't route them anymore
	for _, r := range registrations {
		r.State = "expired"
		if result := db.Save(&r); result.Error != nil {
			incErrorCount("internal")
			log.Println("Internal error, unable to execute query:", result.Error)
			mutex.Unlock()
			continue
		}

		debug("Removing client tunnel for registration %+v\n", r)
		err := removeClientTunnel(sViper, r.ClientTunnelName)
		if err != nil {
			incErrorCount("internal")
			log.Println("Internal error, unable to remove client tunnel", err)
			return
		}

		if result := db.Delete(&r); result.Error != nil {
			incErrorCount("internal")
			log.Println("Internal error, unable to execute query:", result.Error)
			continue
		}
	}
	mutex.Unlock()

	err := countValidLeases(db)
	if err != nil {
		incErrorCount("internal")
		log.Println("Internal error, unable to count valid leases", err)
		return
	}
}

// ServerMain is the main() function for the server program
func ServerMain() {
	sViper = viper.New()
	setupLogWriters(sViper, false)

	// Enable the Prometheus endpoint
	enablePrometheus = true

	fs := serverLoadConfig("", os.Args[1:])

	// Make sure we have a version of yggdrasil that is recent enough
	legacy, version, err := legacyYggdrasil()
	if err != nil {
		Fatal(err)
	}
	if legacy {
		err = fmt.Errorf("The detected version of yggdrasil (%s) is too old, it is not supported by this version of autoygg.\nPlease upgrade yggdrasil to version 0.4.0 or later, or downgrade autoygg to v0.2.2", version)
		Fatal(err)
	}

	// if GatewayPublicKey is not set in the config, calculate it here.
	// This has the advantage that --help and --version are already handled
	// at this point, so these calls won't error out if yggdrasil is not
	// installed or the user doesn't have enough permissions to talk to it.
	if sViper.GetString("GatewayPublicKey") == "" {
		gatewayPublicKey, err := getSelfPublicKey()
		if err != nil {
			incErrorCount("yggdrasil")
			fmt.Printf("Error: unable to run yggdrasilctl: %s\n", err)
			os.Exit(1)
		} else {
			sViper.Set("GatewayPublicKey", gatewayPublicKey)
		}
	}

	if sViper.GetBool("DumpConfig") {
		fmt.Print(dumpConfiguration(sViper, "server"))
		os.Exit(0)
	}
	debug(dumpConfiguration(sViper, "server"))

	if sViper.GetString("StateDir") == "" {
		fmt.Println("Error: StateDir must not be empty. Please check the configuration file.")
		serverUsage(fs)
		os.Exit(1)
	}

	if _, err := os.Stat(sViper.GetString("StateDir")); os.IsNotExist(err) {
		err = os.MkdirAll(sViper.GetString("StateDir"), os.FileMode(0700))
		if err != nil {
			Fatal(err)
		}
	}

	db := setupDB("sqlite3", sViper.GetString("StateDir")+"/autoygg.db", sViper.GetBool("DatabaseDebug"))
	defer db.Close()
	r := setupRouter(db)

	setup()

	err = loadLeases(db)
	if err != nil {
		Fatal(err)
	}

	go expireLeases(db, &mutex)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		err := r.Run("[" + sViper.GetString("ListenHost") + "]:" + sViper.GetString("ListenPort"))
		if err != nil {
			log.Print("Starting autoygg server daemon")
			handleError(err, sViper, false)
		}
	}()
	<-sig
	fmt.Print("\r") // Overwrite any ^C that may have been printed on the screen
	tearDown()
}
