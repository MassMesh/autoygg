# Server Operating Model

## Models

Example Config

    ListenHost: "the:yggdrasil:ip:address:of:the:autoygg:server"
    ListenPort: 8080
    GatewayOwner: "You <you@example.com>"
    GatewayDescription: "This is an Yggdrasil gateway operated for fun and profit"
    RequireRegistration: false
    RequireApproval: false
    WhitelistEnabled: true
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
    	ClientInfo       string // Registration info?
    	Error            string
    	Approved         Bool
    }

Lease Model

    type lease struct {
    	gorm.Model
    	YggIP            string // Client Yggdrasil IP address
    	PublicKey        string // Client Yggdrasil PublicKey
    	GatewayPublicKey string
    	ClientIP         string // The tunnel IP address assigned to the client
    	ClientNetMask    int    // The tunnel netmask
    	ClientGateway    string
    	LeaseExpires     time.Time
    }

ACL Model

    type acl struct {
      YggIP string
      Access bool      // True for whitelisted, false for blacklisted
      Comment string
    }

## Operating Modes
### Full Anonymous
* Allows anybody to directly `GET /lease` to use the gateway, subject to ACL config
* RequireRegistration = false

### Registration
* Requires all gateway users to first `POST /register` to store personal information with the gateway before requesting `POST /lease`
* RequireRegistration = true
* RequireApproval = false

### Registration & Approval
* Requires all gateway users to `POST /register` and wait for the gateway admin to manually approve the registration before the user is allowed to `POST /lease`
* RequireRegistration = true
* RequireApproval = true

## Endpoints
  * `GET /info`: Returns GatewayOwner, Description, RequireRegistration, ACLEnabled
  * `GET /register`:
    * Return access error if ACL check fails
    * If RequireRegistration=false: Disabled
    * If RequireRegistration=true: Return registration status for user if found or 404
  * `POST /register`:
    * Return access error if ACL check fails
    * If RequireRegistration=false, Disabled
    * If ACLEnabled=true, apply ACLFile based on ACLMode, give access error if conditions not met
    * If RequireRegistration=true, Store registration information with Approved=false
      * Storing unapproved feels like the safer thing to do in case someone switches RequireApproval on and off
  * `POST /renew`:
    * Return access error if ACL check fails
    * If RequireRegistration=true: Deny unless approved registration found
    * If ACLEnabled=true, apply ACLFile based on ACLMode, give access error if conditions not met
    * Assign lease, provision lease, and store in leases table
  * `POST /release`:
    * Return access error if ACL check fails
    * Remove lease from leases, teardown lease, and return success. Return 404 if lease doesn't exist
  * ACL Check Routine:
    * If blacklist entry exists with client IP
      * Return access error
    * If WhitelistEnabled=true and whitelist entry does not exist with client IP
      * Return access error

# Client Operating Model
