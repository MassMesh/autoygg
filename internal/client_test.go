package internal

import (
	"context"

	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

var serverConfigDir string
var srv *http.Server

func StopServer(c *check.C) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		c.Fatal("Server forced to shutdown:", err)
	}
}

func StartServer(c *check.C) {
	serverLoadConfig(serverConfigDir)

	db := setupDB("sqlite3", viper.GetString("StateDir")+"/autoygg.db")
	defer db.Close()
	r := setupRouter(db)

	srv = &http.Server{
		Addr:    "[" + viper.GetString("ListenHost") + "]:" + viper.GetString("ListenPort"),
		Handler: r,
	}

	go func() {
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

	// Populate a custom config file
	serverYaml := []byte("---\nListenHost: \"::1\"\nListenPort: \"61234\"\nStateDir: \"" + serverConfigDir + "\"\n")
	configFile := filepath.Join(serverConfigDir, "server.yaml")
	err = ioutil.WriteFile(configFile, serverYaml, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}

	StartServer(c)
}

func (s *Suite) TearDownSuite(c *check.C) {
	defer os.RemoveAll(serverConfigDir)
	StopServer(c)
}

func (*Suite) TestConfigLoading(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "autoygg-client-test")
	if err != nil {
		c.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Load default config
	clientCreateFlagSet()

	// Test defaults
	c.Assert(viper.GetBool("daemon"), check.Equals, true)
	c.Assert(viper.GetBool("debug"), check.Equals, false)
	c.Assert(viper.GetBool("quiet"), check.Equals, false)
	c.Assert(viper.GetBool("dumpConfig"), check.Equals, false)
	c.Assert(viper.GetString("action"), check.Equals, "register")
	c.Assert(viper.GetString("gatewayHost"), check.Equals, "")
	c.Assert(viper.GetString("gatewayPort"), check.Equals, "8080")
	c.Assert(viper.GetString("defaultGatewayIP"), check.Equals, "")
	c.Assert(viper.GetString("defaultGatewayDev"), check.Equals, "")
	c.Assert(viper.GetString("yggdrasilInterface"), check.Equals, "tun0")

	// Populate a custom config file
	clientYaml := []byte("---\nGatewayHost: \"2001:db8::1\"\nGatewayPort: \"9090\"\n")
	configFile := filepath.Join(tmpDir, "client.yaml")
	err = ioutil.WriteFile(configFile, clientYaml, 0644)
	if err != nil {
		c.Fatalf("Couldn't write file %s", configFile)
	}

	// Load custom config file and make sure the values are read back correctly
	clientLoadConfig(tmpDir)
	c.Assert(viper.GetString("gatewayHost"), check.Equals, "2001:db8::1")
	c.Assert(viper.GetString("gatewayPort"), check.Equals, "9090")
}

func (*Suite) TestInfoCall(c *check.C) {
	// Load default config
	fs := clientCreateFlagSet()

	i, err := doInfoRequest(fs, "::1", "61234")

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
