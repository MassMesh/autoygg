# Server Operating Model

## Models

Example Config (anonymous mode)

    ListenHost: "the:yggdrasil:ip:address:of:the:autoygg:server"
    ListenPort: 8080
    GatewayOwner: "You <you@example.com>"
    GatewayDescription: "This is an Yggdrasil gateway operated for fun and profit"
    RequireRegistration: false
    AccessListEnabled: false
    StateDir: "/var/lib/autoygg"
    MaxClients: 10
    LeaseTimeoutSeconds: 14400
    GatewayTunnelIP: "10.42.0.1"
    GatewayTunnelNetmask: 16
    GatewayTunnelIPRangeMin: "10.42.42.1"
    GatewayTunnelIPRangeMax: "10.42.42.255"
    Debug: false

Registration Model

    type registration struct {
      gorm.Model
      YggIP            string // Client Yggdrasil IP address
      PublicKey        string // Client Yggdrasil PublicKey
      ClientName       string // Registration name (optional depending on operating mode)
      ClientEmail      string // Registration email (optional depending on operating mode)
      ClientPhone      string // Registration phone (optional depending on operating mode)
      ClientIP         string // The tunnel IP address assigned to the client
      ClientNetMask    int    // The tunnel netmask
      ClientGateway    string
      Error            string
      Approved         Bool
      LeaseExpires     time.Time
    }

ACL Model

    type acl struct {
      YggIP string
      Access bool      // True for allowed, false for denied
      Comment string
    }

## Operating Modes
### Full Anonymous
* Allows anybody to do `POST /register` without sending personal information
* Access granted automatically
* RequireRegistration = false
* AccessListEnabled = false

### Registration
* Requires all users to do `POST /register` with personal information (name, phone, e-mail)
* Access granted automatically
* RequireRegistration = true
* AccessListEnabled = false

### Registration & Approval
* Requires all users to do `POST /register` with personal information (name, phone, e-mail)
* Must wait for the gateway admin to manually approve the registration to use the gateway by adding an entry to the AccessList
* RequireRegistration = true
* AccessListEnabled = true

### Full Anonymous & Approval
* Allows anybody to do `POST /register` without sending personal information
* Must wait for the gateway admin to manually approve the registration to use the gateway by adding an entry to the AccessList
* RequireRegistration = false
* AccessListEnabled = false

## ACL Modes
### ACL disabled
* Allows anyone with a valid registration to use the gateway
* AccessListEnabled = false

### ACL enabled
* Allows only valid registrations with an ACL entry set to `access: true` to use the gateway
* AccessListEnabled = true

## ACL Check Routine:
* If ACL entry exists for client IP with Access: false
  * Return access error
* If AccessListEnabled=true and ACL entry does not exist for client IP with Access: true
  * Return access error

## Endpoints
  * `GET /info`: Returns GatewayOwner, Description, RequireRegistration, AccessListEnabled
  * `GET /register`:
    * If AccessListEnabled=true, apply ACLs, return access error if access denied
    * If Registration is found, return status, otherwise return error
  * `POST /register`:
    * If AccessListEnabled=true, apply ACLs, return access error if access denied
    * If RequireRegistration=true: require ClientName, ClientEmail, ClientPhone to be populated, otherwise return error
    * Create Registration, provision client
  * `POST /renew`:
    * If AccessListEnabled=true, apply ACLs, return access error if access denied
    * If RequireRegistration=true: require ClientName, ClientEmail, ClientPhone to be populated, otherwise return error
    * If Registration is found, extend lease expiry date, otherwise return error
  * `POST /release`:
    * If AccessListEnabled=true, apply ACLs, return access error if access denied
    * Remove Registration, unprovision client, and return success. Return 404 if lease doesn't exist

# Client Operating Model
