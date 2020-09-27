package internal

import (
	"context"

	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

const GatewayPort = "61234"

var _ = check.Suite(&Suite{})

type Suite struct{}

var YggAddress string
var serverConfigDir string
var srv *http.Server
var db *gorm.DB

func StopServer(c *check.C) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		c.Fatal("Server forced to shutdown:", err)
	}
}

func StartServer(c *check.C) {
	sViper = viper.New()
	serverLoadConfig(serverConfigDir)

	db = setupDB("sqlite3", sViper.GetString("StateDir")+"/autoygg.db")
	r := setupRouter(db)

	srv = &http.Server{
		Addr:    "[" + sViper.GetString("ListenHost") + "]:" + sViper.GetString("ListenPort"),
		Handler: r,
	}

	go func() {
		defer db.Close()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.Fatal(err)
		}
	}()
}

func (s *Suite) SetUpSuite(c *check.C) {
	var err error
	serverConfigDir, err = ioutil.TempDir("", "autoygg-server-test")
	if err != nil {
		c.Fatal(err)
	}

	// Get our own Yggdrasil Address
	YggAddress, err = getSelfAddress()
	c.Assert(err, check.Equals, nil)

	// Populate a custom config file
	writeServerConfig(c, []byte("---\nListenHost: \""+YggAddress+"\"\nListenPort: \""+GatewayPort+"\"\nStateDir: \""+serverConfigDir+"\""))

	// And an empty accessList file
	writeAccessList(c, []byte("AccessList:\n"))

	StartServer(c)
}

// Changing the access list file will trigger an automatic config reload in the server
func writeAccessList(c *check.C, accessList []byte) {
	accessListFile := filepath.Join(serverConfigDir, "accesslist.yaml")
	writeFile(c, accessListFile, accessList)
}

// Changing the server config file will trigger an automatic config reload in the server,
// but changing configuration that is only used at startup will require a restart of the
// server.
func writeServerConfig(c *check.C, serverConfig []byte) {
	configFile := filepath.Join(serverConfigDir, "server.yaml")
	writeFile(c, configFile, serverConfig)
}

func writeFile(c *check.C, path string, contents []byte) {
	err := ioutil.WriteFile(path, contents, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", path)
	}
}

func (s *Suite) TearDownSuite(c *check.C) {
	//defer os.RemoveAll(serverConfigDir)
	StopServer(c)
}

func (*Suite) TestConfigLoading(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Load default config
	cViper = viper.New()
	clientCreateFlagSet()

	// Test defaults
	c.Assert(cViper.GetBool("daemon"), check.Equals, true)
	c.Assert(cViper.GetBool("debug"), check.Equals, false)
	c.Assert(cViper.GetBool("quiet"), check.Equals, false)
	c.Assert(cViper.GetBool("dumpConfig"), check.Equals, false)
	c.Assert(cViper.GetString("action"), check.Equals, "register")
	c.Assert(cViper.GetString("gatewayHost"), check.Equals, "")
	c.Assert(cViper.GetString("gatewayPort"), check.Equals, "8080")
	c.Assert(cViper.GetString("defaultGatewayIP"), check.Equals, "")
	c.Assert(cViper.GetString("defaultGatewayDev"), check.Equals, "")
	c.Assert(cViper.GetString("yggdrasilInterface"), check.Equals, "tun0")

	// Populate a custom config file
	clientYaml := []byte("---\nGatewayHost: \"2001:db8::1\"\nGatewayPort: \"9090\"\n")
	configFile := filepath.Join(tmpDir, "client.yaml")
	err = ioutil.WriteFile(configFile, clientYaml, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}

	// Load custom config file and make sure the values are read back correctly
	clientLoadConfig(tmpDir)
	c.Assert(cViper.GetString("gatewayHost"), check.Equals, "2001:db8::1")
	c.Assert(cViper.GetString("gatewayPort"), check.Equals, "9090")
}

func (*Suite) TestInfo(c *check.C) {
	// Load default config
	fs := clientCreateFlagSet()

	i, err := doInfoRequest(fs, YggAddress, GatewayPort)

	c.Assert(err, check.Equals, nil)
	c.Check(i.GatewayOwner, check.Equals, "Some One <someone@example.com>")
	c.Check(i.Description, check.Equals, "This is an Yggdrasil internet gateway")
	c.Check(i.Network, check.Equals, "Name of the egress network or ISP")
	c.Check(i.Location, check.Equals, "Physical location of the gateway")
	c.Check(i.GatewayInfoURL, check.Equals, "")
	c.Check(i.SoftwareVersion, check.Equals, "dev")
	c.Check(i.RequireRegistration, check.Equals, true)
	c.Check(i.RequireApproval, check.Equals, true)
	c.Check(i.AccessListEnabled, check.Equals, true)
}

func CustomClientConfig(c *check.C) (tmpDir string) {
	tmpDir, err := ioutil.TempDir("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}

	// Populate a custom config file
	clientYaml := []byte("---\nGatewayHost: \"" + YggAddress + "\"\nGatewayPort: \"" + GatewayPort + "\"\nStateDir: \"" + tmpDir + "\"\n")
	configFile := filepath.Join(tmpDir, "client.yaml")
	err = ioutil.WriteFile(configFile, clientYaml, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}
	fmt.Println(tmpDir)
	fmt.Println(string(clientYaml))
	return
}

func (*Suite) TestRegistration(c *check.C) {
	// Load default config
	fs := clientCreateFlagSet()

	tmpDir := CustomClientConfig(c)
	defer os.RemoveAll(tmpDir)

	// Load default config
	cViper = viper.New()
	clientCreateFlagSet()
	clientLoadConfig(tmpDir)

	var err error
	var State state
	State, err = loadState(State)
	c.Assert(err, check.Equals, nil)

	writeAccessList(c, []byte("AccessList:\n"))
	writeServerConfig(c, []byte("---\nListenHost: \""+YggAddress+"\"\nListenPort: \""+GatewayPort+"\"\nStateDir: \""+serverConfigDir+"\"\n"))

	// Try to register when our address is not on the accesslist
	r, State, err := doRequest(fs, "register", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "Registration not allowed")

	writeAccessList(c, []byte("AccessList:\n  - yggip: "+YggAddress+"\n    access: true\n    comment: TestRegistration\n"))

	r, State, err = doRequest(fs, "register", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "")

	loadedState, err := loadState(state{})
	c.Assert(err, check.Equals, nil)
	c.Assert(loadedState.State, check.Equals, "connected")

	r, State, err = doRequest(fs, "renew", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "")

	r, State, err = doRequest(fs, "release", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "")

	loadedState, err = loadState(state{})
	c.Assert(err, check.Equals, nil)
	c.Assert(loadedState.State, check.Equals, "disconnected")

	// Release non-existent lease
	r, State, err = doRequest(fs, "release", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "Registration not found")

	// Renew non-existent lease
	r, _, err = doRequest(fs, "renew", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "Registration not found")
}

func (*Suite) TestLeaseExpiration(c *check.C) {
	// Load default config
	fs := clientCreateFlagSet()

	tmpDir := CustomClientConfig(c)
	defer os.RemoveAll(tmpDir)

	clientLoadConfig(tmpDir)

	var err error
	var State state
	State, err = loadState(State)
	c.Assert(err, check.Equals, nil)
	fmt.Println("ABOUT TO REWRITE CONFIG")

	// Set LeaseTimeoutSeconds to zero seconds
	writeServerConfig(c, []byte("---\nListenHost: \""+YggAddress+"\"\nListenPort: \""+GatewayPort+"\"\nStateDir: \""+serverConfigDir+"\"\nLeaseTimeoutSeconds: 0\n"))
	writeAccessList(c, []byte("AccessList:\n  - yggip: "+YggAddress+"\n    access: true\n    comment: TestRegistration\n"))

	r, State, err := doRequest(fs, "register", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "")

	// Purge the expired lease (we have LeaseTimeoutSeconds configured to 0 seconds)
	expireLeasesWorker(db, &mutex)

	// Renew expired lease
	r, _, err = doRequest(fs, "renew", YggAddress, GatewayPort, State)
	c.Assert(err, check.Equals, nil)
	c.Assert(r.Error, check.Equals, "Registration not found")
}

func (*Suite) TestDiscoverLocalGateway(c *check.C) {
	// This partial route list has a blackhole route followed by a route via ygg0 followed by the lan default route
	// parseLinuxProcNetRoute must return the lan default route.
	b := []byte("Iface\tDestination\tGateway\n*\t0A0A0A0A\t00000000\nygg0\t00000000\t01002A0A\nbr-lan\t00000000\t01002A0A\n")
	gwdev, gwip, err := parseLinuxProcNetRoute("ygg0", b)
	c.Assert(err, check.IsNil)
	c.Assert(net.IP(gwip).String(), check.Equals, "10.42.0.1")
	c.Assert(gwdev, check.Equals, "br-lan")
}
