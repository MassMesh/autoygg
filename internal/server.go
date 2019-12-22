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
  "os"
  "os/exec"
  "strings"
  "time"
)

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
      c.JSON(http.StatusInternalServerError, Registration{Error: "Internal Server Error"})
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
    c.JSON(http.StatusBadRequest, Registration{Error: "Malformed json request"})
    c.Abort()
    err = e
    return
  }
  if len(registration.PublicKey) != 64 {
    c.JSON(http.StatusBadRequest, Registration{Error: "Malformed json request: PublicKey length incorrect"})
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
    c.JSON(http.StatusForbidden, Registration{Error: "Registration disabled on server"})
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
      c.JSON(http.StatusNotFound, Registration{Error: "Registration not found"})
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
    QueueAddRemoteSubnet(db,registration.ID)
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
  ServerRemoveRemoteSubnet(db, registration.ID)

  c.JSON(http.StatusOK, registration)
  return
}


func newRegistrationHandler(db *gorm.DB, c *gin.Context) {
  var newRegistration Registration
  if err := c.BindJSON(&newRegistration); err != nil {
    c.JSON(http.StatusBadRequest, Registration{Error: "Malformed json request"})
    return
  }
  if len(newRegistration.PublicKey) != 64 {
    c.JSON(http.StatusBadRequest, Registration{Error: "Malformed json request: PublicKey length incorrect"})
    return
  }

  // FIXME take whitelist/blacklist into account
  if ! viper.GetBool("AllowRegistration") {
    c.JSON(http.StatusForbidden, Registration{Error: "Registration disabled on server"})
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
    c.JSON(http.StatusInternalServerError, Registration{Error: "Internal Server Error"})
    return
  }
  QueueAddRemoteSubnet(db,newRegistration.ID)

  c.JSON(http.StatusOK, newRegistration)
  return
}

func QueueAddRemoteSubnet(db *gorm.DB, ID uint) {
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
  // FIXME: actually queue this, rather than doing it inline
  err := AddRemoteSubnet(registration.ClientIP + "/32", registration.PublicKey)

  if err != nil {
    incErrorCount("yggdrasil")
    log.Printf("Yggdrasil error, unable to run command: %s", err)
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

//FIXME refactor check out RemoveRemoteSubnet
func ServerRemoveRemoteSubnet(db *gorm.DB, ID uint) {
  var registration Registration
  if result := db.First(&registration, ID); result.Error != nil {
    incErrorCount("internal")
    log.Println("Internal error, unable to execute query:", result.Error)
    return
  }

  command := viper.GetString("GatewayRemoveRemoteSubnetCommand")
  command = strings.Replace(command, "%%SUBNET%%", registration.ClientIP + "/32", -1)
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


func SetupRouter(db *gorm.DB) (r *gin.Engine) {
  gin.SetMode(gin.ReleaseMode)
  r = gin.Default()

  if EnablePrometheus {
    p := enablePrometheusEndpoint()
    p.Use(r)
    err := prometheus.Register(errorCount)
    log.Printf("Enabling Prometheus endpoint")
    HandleError(err,false)
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
    Fatal("Couldn't initialize database connection")
  }
  db.LogMode(true)

  // Migrate the schema
  db.AutoMigrate(&Registration{})

  return
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
  viper.SetDefault("GatewayTunnelIP", "10.42.0.1")
  viper.SetDefault("GatewayTunnelNetMask", 16)
  viper.SetDefault("GatewayTunnelIPRangeMin", "10.42.42.1") // Minimum IP for "DHCP" range
  viper.SetDefault("GatewayTunnelIPRangeMax", "10.42.42.255") // Maximum IP for "DHCP" range
  viper.SetDefault("GatewayAddRemoteSubnetCommand", "/usr/bin/yggdrasilctl addremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")
  viper.SetDefault("GatewayRemoveRemoteSubnetCommand", "/usr/bin/yggdrasilctl removeremotesubnet subnet=%%SUBNET%% box_pub_key=%%CLIENT_PUBLIC_KEY%%")
  err, gatewayPublicKey := GetSelfPublicKey()
  if err != nil {
    incErrorCount("yggdrasil")
    log.Printf("Error: unable to run yggdrasilctl: %s",err)
  } else {
    viper.SetDefault("GatewayPublicKey", gatewayPublicKey)
  }

}

func LoadConfig(path string) {
  loadConfigDefaults()

  viper.SetEnvPrefix("AUTOYGG") // will be uppercased automatically
  err := viper.BindEnv("CONFIG")
  if err != nil {
    Fatal(fmt.Sprintln("Fatal error:", err.Error()))
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
    Fatal(fmt.Sprintln("Fatal error reading config file:", err.Error()))
  }
}

func EnableIPForwarding() (err error) {
  f, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward",os.O_RDWR,0644)
  if err != nil {
    return
  }
  defer f.Close()
  _, err = f.WriteString("1")
  if err != nil {
    fmt.Println(err)
    return
  }
  return
}

func ServerMain() {
  SetupLogWriter()

  // Enable the Prometheus endpoint
  EnablePrometheus = true

  LoadConfig("")
  db := SetupDB("sqlite3",viper.GetString("StateDir") + "/autoygg.db")
  defer db.Close()
  r := SetupRouter(db)
  log.Printf("Enabling IP forwarding")
  err := EnableIPForwarding()
  HandleError(err,true)
  log.Printf("Enabling Yggdrasil tunnel routing")
  err = EnableTunnelRouting()
  HandleError(err,true)
  log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
  err = AddLocalSubnet("0.0.0.0/0")
  HandleError(err,true)
  log.Printf("Adding tunnel IP %s/%d",viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  err = AddTunnelIP(viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  HandleError(err,true)
  // FIXME todo defer tearing down the config we added?
  r.Run("[" + viper.GetString("ListenHost")+"]:"+viper.GetString("ListenPort"))
}

