# Server Operating Model

## Models

Example Config

    ListenHost: "the:yggdrasil:ip:address:of:the:autoygg:server"
    ListenPort: 8080
    GatewayOwner: "You <you@example.com>"
    GatewayDescription: "This is an Yggdrasil gateway operated for fun and profit"
    RequireRegistration: false
    RequireApproval: false
    AccessListEnabled: true
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
      ClientName       string // Registration name (optional)
      ClientEmail      string // Registration email (optional)
      ClientPhone      string // Registration phone (optional)
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
* Allows anybody to do `POST /register` without sending personal information to use the gateway
* Subject to ACL configuration
* RequireRegistration = false

### Registration
* Requires all users to do `POST /register` with personal information (name, phone, e-mail) to use the gateway
* Subject to ACL configuration
* RequireRegistration = true
* RequireApproval = false

### Registration & Approval
* Requires all users to `POST /register` and wait for the gateway admin to manually approve the registration to use the gateway
* Subject to ACL configuration
* RequireRegistration = true
* RequireApproval = true

## ACL Modes
### ACL disabled
* Allows anyone with a valid registration to use the gateway
* AccessListEnabled = false

### ACL enabled
* Allows only valid registrations with an ACL entry set to `access: true` to use the gateway
* AccessListEnabled = true
* AccessListEnabled = true

## Endpoints
  * `GET /info`: Returns GatewayOwner, Description, RequireRegistration, RequireApproval, AccessListEnabled
  * `GET /register`:
    * Return access error if ACL check fails
    * If RequireRegistration=false: Disabled
    * If RequireRegistration=true: Return registration status for user if found or 404
  * `POST /register`:
    * Return access error if ACL check fails
    * If RequireRegistration=false, Disabled
    * If AccessListEnabled=true, apply AccessListFile, return access error if access denied
    * If RequireRegistration=true, Store registration information with Approved=false
      * Storing unapproved feels like the safer thing to do in case someone switches RequireApproval on and off
  * `POST /renew`:
    * Return access error if ACL check fails
    * If RequireRegistration=true: Deny unless approved registration found
    * If AccessListEnabled=true, apply AccessListFile, return access error if access denied
    * Assign lease, provision lease, and store in leases table
  * `POST /release`:
    * Return access error if ACL check fails
    * Remove lease from leases, teardown lease, and return success. Return 404 if lease doesn't exist
  * ACL Check Routine:
    * If acl entry exists for client IP with Access: false
      * Return access error
    * If AccessListEnabled=true and acl entry does not exist for client IP with Access: true
      * Return access error

# Client Operating Model
