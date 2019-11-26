package internal

import (
  "errors"
  "fmt"
  "github.com/gin-gonic/gin"
  "github.com/spf13/viper"
  "github.com/prometheus/client_golang/prometheus"
  "github.com/zsais/go-gin-prometheus"
  "github.com/jinzhu/gorm"
  _ "github.com/jinzhu/gorm/dialects/sqlite"
  "log"
  "net"
  "net/http"
  "os/exec"
  "strings"
  "time"
)

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
  State        string
  PublicKey    string
  YggIP        string  // The Yggdrasil IP address
  ClientIP     string  // The tunnel IP address assigned to the client
  ClientInfo   string
  LeaseExpires time.Time
}

var errorCount = prometheus.NewCounterVec(
  prometheus.CounterOpts{
    Name: "autoygg_error_count",
    Help: "count error by type",
  },
  []string{"type"},
)

func incErrorCount(errorType string) {
  errorCount.WithLabelValues(errorType).Inc()
}

func enablePrometheusEndpoint() (p *ginprometheus.Prometheus) {
  // Enable basic Prometheus metrics
  p = ginprometheus.NewPrometheus("autoygg")
  return
}

func registerHandler(db *gorm.DB, c *gin.Context) {
  var existingRegistration Registration
  statusCode := http.StatusOK

  // FIXME take whitelist/blacklist into account
  if ! viper.GetBool("AllowRegistration") {
    statusCode = http.StatusForbidden
    c.JSON(statusCode, existingRegistration)
    return
  }

  if result := db.Where("ygg_ip = ?",c.ClientIP()).First(&existingRegistration); result.Error != nil {
    // IsRecordNotFound is normal if we haven't seen this public key before
    if gorm.IsRecordNotFoundError(result.Error) {
      statusCode = http.StatusNotFound
    } else {
      incErrorCount("internal")
      log.Println("Internal error, unable to execute query:", result.Error)
      c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
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
  for count == 0 && IP.String() != ipMax {
    IP = nextIP(IP, 1)
    db.Model(&Registration{}).Where("client_ip = ?", IP).Count(&count)
  }
  return IP.String()
}

func bindRegistration(c *gin.Context) (err error, registration Registration) {
  if e := c.BindJSON(&registration); e != nil {
    c.JSON(http.StatusBadRequest, gin.H{"Error": "Malformed json request"})
    c.Abort()
    err = e
    return
  }
  if len(registration.PublicKey) != 64 {
    c.JSON(http.StatusBadRequest, gin.H{"Error": "Malformed json request: PublicKey length incorrect"})
    c.Abort()
    err = errors.New("Malformed json request: PublicKey length incorrect")
    registration = Registration{}
    return
  }
  // FIXME validate that provided public key matches IPv6 address

  return
}

func validateRegistration(c *gin.Context) (err error) {
  // FIXME take whitelist/blacklist into account
  if ! viper.GetBool("AllowRegistration") {
    c.JSON(http.StatusForbidden, gin.H{"Error": "Registration disabled on server"})
    c.Abort()
    return
  }
  return
}

func authorized(db *gorm.DB, c *gin.Context) (err error, registration Registration, existingRegistration Registration) {
  err, registration = bindRegistration(c)
  if err != nil {
    return
  }
  err = validateRegistration(c)
  if err != nil {
    return
  }

  if result := db.Where("ygg_ip = ?",c.ClientIP()).First(&existingRegistration); result.Error != nil {
    if gorm.IsRecordNotFoundError(result.Error) {
      c.JSON(http.StatusNotFound, gin.H{"Error": "Registration not found"})
      c.Abort()
      err = result.Error
      return
    } else {
      incErrorCount("internal")
      log.Println("Internal error, unable to execute query:", result.Error)
      c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
      c.Abort()
      err = result.Error
      return
    }
  }
  return
}

func renewHandler(db *gorm.DB, c *gin.Context) {
  err, registration, existingRegistration := authorized(db,c)
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
    AddRemoteSubnet(db,registration.ID)
  }

  c.JSON(http.StatusOK, registration)
  return
}

func releaseHandler(db *gorm.DB, c *gin.Context) {
  err, registration, existingRegistration := authorized(db,c)
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
  RemoveRemoteSubnet(db, registration.ID)

  c.JSON(http.StatusOK, registration)
  return
}


func newRegistrationHandler(db *gorm.DB, c *gin.Context) {
  var newRegistration Registration
  if err := c.BindJSON(&newRegistration); err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"Error": "Malformed json request"})
    return
  }
  if len(newRegistration.PublicKey) != 64 {
    c.JSON(http.StatusBadRequest, gin.H{"Error": "Malformed json request: PublicKey length incorrect"})
    return
  }

  // FIXME take whitelist/blacklist into account
  if ! viper.GetBool("AllowRegistration") {
    c.JSON(http.StatusForbidden, gin.H{"Error": "Registration disabled on server"})
    return
  }

  // Assign a client IP and save it in the database
  // FIXME verify ipv6 <=> public key
  var existingRegistration Registration
  if result := db.Where("public_key = ?",newRegistration.PublicKey).First(&existingRegistration); result.Error != nil {
    // IsRecordNotFound is normal if we haven't seen this public key before
    if ! gorm.IsRecordNotFoundError(result.Error) {
      incErrorCount("internal")
      log.Println("Internal error, unable to execute query:", result.Error)
      c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
      return
    }
  }

  if existingRegistration == (Registration{}) {
    // First time we've seen this public key
    newRegistration.ClientIP = newIPAddress(db)
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
    c.JSON(http.StatusInternalServerError, gin.H{"Error": "Internal Server Error"})
    return
  }
  AddRemoteSubnet(db,newRegistration.ID)

  c.JSON(http.StatusOK, newRegistration)
  return
}

// FIXME: queue this, rather than doing it inline
func AddRemoteSubnet(db *gorm.DB, ID uint) {
  var registration Registration
  if result := db.First(&registration, ID); result.Error != nil {
    incErrorCount("internal")
    log.Println("Internal error, unable to execute query:", result.Error)
    return
  }
  if registration.State != "open" && registration.State != "fail" {
    // Nothing to do!
    return
  }
  command := viper.GetString("GatewayAddRemoteSubnetCommand")
  command = strings.Replace(command, "%%SUBNET%%", registration.ClientIP, -1)
  command = strings.Replace(command, "%%CLIENT_PUBLIC_KEY%%", registration.PublicKey, -1)

  fmt.Println(command)
  commandSlice := strings.Split(command," ")
  cmd := exec.Command(commandSlice[0],commandSlice[1:]...)
  err := cmd.Run()

  if err != nil {
    incErrorCount("yggdrasil")
    log.Printf("Yggdrasil error, unable to run %s: %s", command, err)
    registration.State = "fail"
  } else {
    registration.State = "success"
  }

  if result := db.Save(&registration); result.Error != nil {
    incErrorCount("internal")
    log.Println("Internal error, unable to execute query:", result.Error)
    return
  }
}

func RemoveRemoteSubnet(db *gorm.DB, ID uint) {
  var registration Registration
  if result := db.First(&registration, ID); result.Error != nil {
    incErrorCount("internal")
    log.Println("Internal error, unable to execute query:", result.Error)
    return
  }

  command := viper.GetString("GatewayRemoveRemoteSubnetCommand")
  command = strings.Replace(command, "%%SUBNET%%", registration.ClientIP, -1)
  command = strings.Replace(command, "%%CLIENT_PUBLIC_KEY%%", registration.PublicKey, -1)

  fmt.Println(command)
  commandSlice := strings.Split(command," ")
  cmd := exec.Command(commandSlice[0],commandSlice[1:]...)
  err := cmd.Run()

  if err != nil {
    incErrorCount("yggdrasil")
    log.Printf("Yggdrasil error, unable to run %s: %s", command, err)
    registration.State = "fail"
  } else {
    registration.State = "removed"
  }

  if result := db.Delete(&registration); result.Error != nil {
    incErrorCount("internal")
    log.Println("Internal error, unable to execute query:", result.Error)
    return
  }
}


func SetupRouter(db *gorm.DB, enablePrometheus bool) (r *gin.Engine) {
  r = gin.Default()

  if enablePrometheus {
    p := enablePrometheusEndpoint()
    p.Use(r)
    prometheus.MustRegister(errorCount)
  }

  // Define routes for unauthenticated requests
  noAuth := r.Group("/")
  {
    noAuth.GET("/info", func(c *gin.Context) {
      res := Info{
        GatewayOwner: viper.GetString("GatewayOwner"),
        Description: viper.GetString("GatewayDescription"),
        RegistrationRequired: viper.GetBool("AllowRegistration") && len(viper.GetStringSlice("Whitelist")) != 0, // FIXME: what if you want to run an open gateway? RegistrationRequired: false would suggest that, but it can also mean registration is disabled. Seems suboptimal.
      }
      c.JSON(http.StatusOK, res)
    })
    noAuth.GET("/register", func (c *gin.Context) {
      registerHandler(db,c)
    })
    noAuth.POST("/register", func (c *gin.Context) {
      newRegistrationHandler(db,c)
    })
    noAuth.POST("/renew", func (c *gin.Context) {
      renewHandler(db,c)
    })
    noAuth.POST("/release", func (c *gin.Context) {
      releaseHandler(db,c)
    })

  }
  return
}

func SetupDB(driver string, credentials string) (db *gorm.DB) {
  db, err := gorm.Open(driver, credentials)
  if err != nil {
    fatal("Couldn't initialize database connection")
  }
  db.LogMode(true)

  // Migrate the schema
  db.AutoMigrate(&Registration{})

  return
}

//func yggInterface() {
//  var registrations []Registration
//  db.Where("state = ?","open").Scan(&registrations)
//  for _, r := range registrations {
//
//  }
//}

func fatal (message string) {
  log.Fatal(message)
  incErrorCount("fatal")
}

func loadConfigDefaults() {
  viper.SetDefault("ListenHost", "::1")
  viper.SetDefault("ListenPort", "8080")
  viper.SetDefault("GatewayOwner", "Some One <someone@example.com>")
  viper.SetDefault("GatewayDescription", "This is an Yggdrasil gateway operated for fun.")
  viper.SetDefault("AllowRegistration", false)
  viper.SetDefault("AutoApproveRegistration", false)
  viper.SetDefault("StateDir", "/var/lib/autoygg")
  viper.SetDefault("Whitelist", []string{}) // Unset the Whitelist configuration value to disable the whitelist
  viper.SetDefault("Blacklist", []string{}) // Unset the Blacklist configuration value to disable the blacklist
  viper.SetDefault("MaxClients", 10)
  viper.SetDefault("LeaseTimeoutSeconds", 14400) // Default to 4 hours
  viper.SetDefault("GatewayTunnelIP", "10.42.0.1/16")
  viper.SetDefault("GatewayTunnelIPRangeMin", "10.42.42.1") // Minimum IP for "DHCP" range
  viper.SetDefault("GatewayTunnelIPRangeMax", "10.42.42.255") // Maximum IP for "DHCP" range
  viper.SetDefault("GatewayAddRemoteSubnetCommand", "/usr/bin/yggdrasilctl addremotesubnet subnet=%%SUBNET%%/32 box_pub_key=%%CLIENT_PUBLIC_KEY%%")
  viper.SetDefault("GatewayRemoveRemoteSubnetCommand", "/usr/bin/yggdrasilctl removeremotesubnet subnet=%%SUBNET%%/32 box_pub_key=%%CLIENT_PUBLIC_KEY%%")
}

func EnsureGatewayTunnelIP() {
  out, err := exec.Command("ip","addr","list","tun0").Output()
  if err != nil {
    incErrorCount("ip")
    log.Printf("ip error, unable to run `ip addr list tun0`: %s", err)
  }

  if strings.Index(string(out),viper.GetString("GatewayTunnelIP")) == -1 {
    _, err = exec.Command("ip","addr","add",viper.GetString("GatewayTunnelIP"),"dev","tun0").Output()
    if err != nil {
      incErrorCount("ip")
      log.Printf("ip error, unable to run `ip addr add %s dev tun0`: %s", viper.GetString("GatewayTunnelIP"), err)
    }
  }
}

func LoadConfig(path string) {
  loadConfigDefaults()

  viper.SetEnvPrefix("AUTOYGG") // will be uppercased automatically
  err := viper.BindEnv("CONFIG")
  if err != nil {
    fatal(fmt.Sprintln("Fatal error:", err.Error()))
  }

  config := "config"
  if viper.Get("CONFIG") != nil {
    config = viper.Get("CONFIG").(string)
  }

  viper.SetConfigName(config)
  viper.AddConfigPath(path)
  viper.AddConfigPath("/etc/autoygg/")
  viper.AddConfigPath("$HOME/.autoygg")
  viper.AddConfigPath(".")
  err = viper.ReadInConfig()
  if err != nil {
    fatal(fmt.Sprintln("Fatal error reading config file:", err.Error()))
  }
}

