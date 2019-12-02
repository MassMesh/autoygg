package main

import (
  "fmt"
  "github.com/massmesh/autoygg/internal"
  "github.com/spf13/viper"
  "os"
)

func main() {
  internal.LoadConfig("")
  db := internal.SetupDB("sqlite3",viper.GetString("StateDir") + "/autoygg.db")
  defer db.Close()
  r := internal.SetupRouter(db,true)
  err := internal.AddTunnelIP(viper.GetString("GatewayTunnelIP"),viper.GetInt("GatewayTunnelNetmask"))
  if err != nil {
    fmt.Println(err)
    os.Exit(1)
  }
  r.Run("[" + viper.GetString("ListenHost")+"]:"+viper.GetString("ListenPort"))
}
