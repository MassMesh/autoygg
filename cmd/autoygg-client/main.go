package main

import (
  "bytes"
  "encoding/json"
  "errors"
  "fmt"
  flag "github.com/spf13/pflag"
  "github.com/massmesh/autoygg/internal"
  "io/ioutil"
  "net/http"
  "os"
  "os/exec"
  "regexp"
  //"github.com/spf13/viper"
)

func logFatal(err error) {
  fmt.Printf("\nError: %s\n\n", err.Error())
  os.Exit(1)
}

func doPostRequest(fs *flag.FlagSet, action string, gatewayHost string, gatewayPort string) {
  validActions := map[string]bool{
    "register": true,
    "renew": true,
    "release": true,
  }
  if ! validActions[action] {
    usage(fs)
    logFatal(errors.New("Invalid action: " + action))
  }
  var registration internal.Registration
  registration.PublicKey = getSelfPublicKey()
  req, err := json.Marshal(registration)
  if err != nil {
    logFatal(err)
  }

  resp, err := http.Post("http://[" + gatewayHost + "]:" + gatewayPort + "/" + action, "application/json", bytes.NewBuffer(req))
  if err != nil {
    usage(fs)
    logFatal(err)
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    logFatal(err)
  }

  fmt.Println(string(body))
}

func getSelfPublicKey() (publicKey string) {
  out, err := exec.Command("yggdrasilctl","-v","getSelf").Output()
  if err != nil {
    logFatal(fmt.Errorf("Unable to run `yggdrasilctl -v getSelf`: %s", err))
  }

  re := regexp.MustCompile(`(?m)^Public encryption key: (.*?)$`)
  match := re.FindStringSubmatch(string(out))

  if len(match) < 2 {
    logFatal(errors.New("Unable to parse yggdrasilctl output:" + string(out)))
  }

  publicKey = match[1]

  return
}

func main() {
  var gatewayHost string
  var gatewayPort string
  var action string

  fs := flag.NewFlagSet("Autoygg", flag.ContinueOnError)
  fs.Usage = func() { usage(fs) }

  fs.StringVar(&gatewayHost, "gateway-host", "", "IP address of the gateway host")
  fs.StringVar(&gatewayPort, "gateway-port", "8080", "port of the gateway daemon")
  fs.StringVar(&action, "action", "register", "action (register/renew/release)")

  err := fs.Parse(os.Args[1:])
  if err != nil {
    logFatal(err)
  }

  if gatewayHost == "" || action == "" {
    usage(fs)
    os.Exit(1)
  }

  doPostRequest(fs,action,gatewayHost, gatewayPort)
}
