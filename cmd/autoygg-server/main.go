package main

import (
  "github.com/massmesh/autoygg/internal"
  "github.com/spf13/viper"
  "log"
)

func main() {
  // Initialize our own LogWriter that right justifies all lines at 70 characters
  // and removes the trailing newline from log statements. Used for status lines
  // where we want to write something, then execute a command, and follow with
  // [ok] or [FAIL] on the same line.
  log.SetFlags(0)
  log.SetOutput(new(internal.LogWriter))

  internal.LoadConfig("")
  db := internal.SetupDB("sqlite3",viper.GetString("StateDir") + "/autoygg.db")
  defer db.Close()
  r := internal.SetupRouter(db,true)
  log.Printf("Enabling IP forwarding")
  err := internal.EnableIPForwarding()
  internal.HandleError(err,true)
  log.Printf("Enabling Yggdrasil tunnel routing")
  err = internal.EnableTunnelRouting()
  internal.HandleError(err,true)
  log.Printf("Adding Yggdrasil local subnet 0.0.0.0/0")
  err = internal.AddLocalSubnet("0.0.0.0/0")
  internal.HandleError(err,true)
  log.Printf("Adding tunnel IP %s/%d",viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  err = internal.AddTunnelIP(viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  internal.HandleError(err,true)
  // FIXME todo defer tearing down the config we added?
  r.Run("[" + viper.GetString("ListenHost")+"]:"+viper.GetString("ListenPort"))
}
