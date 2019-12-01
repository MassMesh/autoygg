package main

import (
  "github.com/massmesh/autoygg/internal"
  "github.com/spf13/viper"
)

func main() {
  internal.LoadConfig("")
  db := internal.SetupDB("sqlite3",viper.GetString("StateDir") + "/autoygg.db")
  defer db.Close()
  r := internal.SetupRouter(db,true)
  internal.AddTunnelIP(viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  r.Run("[" + viper.GetString("ListenHost")+"]:"+viper.GetString("ListenPort"))
}
