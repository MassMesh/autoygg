package internal

import (
	"github.com/spf13/viper"

	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

var _ = check.Suite(&Suite{})

type Suite struct{}

var serverConfigDir string

func StopServer(c *check.C) {
}

func StartServer(c *check.C) {
	serverLoadConfig(serverConfigDir)

	db := setupDB("sqlite3", viper.GetString("StateDir")+"/autoygg.db")
	defer db.Close()
	r := setupRouter(db)

	go func() {
		err := r.Run("[" + viper.GetString("ListenHost") + "]:" + viper.GetString("ListenPort"))
		if err != nil {
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
	c.Assert(i.GatewayOwner, check.Equals, "Some One <someone@example.com>")
}
