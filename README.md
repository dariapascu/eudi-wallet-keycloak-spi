# Keycloak EUDI Wallet Verifier — OpenID4VP SPI

A Keycloak **Service Provider Interface (SPI)** that enables user authentication via the **EUDI Android Wallet** using the **OpenID for Verifiable Presentations (OpenID4VP)** protocol. Users present a verifiable credential (Government-issued PID or University Diploma) from their digital wallet and are automatically provisioned and authenticated into Keycloak.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  ┌──────────────┐    OpenID4VP     ┌────────────────────────────────┐   │
│  │  EUDI Android │◄────────────────►│  nginx (port 8443, LAN)       │   │
│  │    Wallet     │  HTTPS / LAN    │        ↓                       │   │
│  │               │                 │  Keycloak + EUDI Verifier SPI  │   │
│  │  ∙ PID        │                 │  (port 9080, localhost)        │   │
│  │  ∙ Diploma    │                 │                                │   │
│  └──────┬────────┘                 │  ∙ Custom Auth Flow            │   │
│         │                          │  ∙ JAR Request Object          │   │
│         │ OpenID4VCI               │  ∙ VP Token Validation         │   │
│         │ (credential issuance)    │  ∙ User Provisioning           │   │
│  ┌──────▼──────────────┐           └──────────────┬─────────────────┘   │
│  │  EAA Issuer          │                         │                     │
│  │  (192.168.x.x)       │           ┌─────────────▼──────────────────┐  │
│  │                      │           │  PoC Web Application (Browser) │  │
│  │  ∙ Issues PID        │           │                                │  │
│  │  ∙ Issues Diploma    │           │  ∙ QR Code display             │  │
│  │  ∙ Revocation CRL    │           │  ∙ Auth status polling         │  │
│  └──────────────────────┘           │  ∙ Profile page                │  │
│                                     └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

The browser and EUDI Wallet run on separate devices but on the **same LAN**. The wallet communicates with Keycloak over HTTPS via **nginx on port 8443**. The browser polls for authentication completion directly (same-origin).

---

## Components

### Keycloak EUDI Verifier SPI (`keycloak-eudi-project/eudi-verifier/`)

A Java SPI plugin for Keycloak 26 that implements the OpenID4VP verification flow. Packaged as a JAR and deployed into Keycloak's `providers/` directory.

| Class | Responsibility |
|---|---|
| `EudiVerifierAuthenticator` | Core authenticator — orchestrates the full OpenID4VP flow |
| `EudiVerifierAuthenticatorFactory` | Registers the authenticator and its configuration properties |
| `RequestObjectJwtBuilder` | Builds signed JAR (JWT Secured Authorization Request) using ES256 |
| `VpTokenValidator` | Validates VP Token: signature (x5c / JWKS), SD-JWT disclosures, KB-JWT, revocation |
| `PresentationDefinitionBuilder` | Generates DCQL queries for PID and Diploma credentials |
| `RequestObjectManager` | Stores and serves Request Objects by reference (5-min expiry) |
| `RequestObjectResource` | REST endpoints: `GET /request/{id}`, `POST /callback`, `GET /status`, `GET /jwks` |
| `SessionStateManager` | Maps OAuth2 `state` to Keycloak auth sessions (10-min timeout) |

### nginx (`keycloak-eudi-project/nginx/`)

Reverse proxy in front of Keycloak. Port 8443 (HTTPS). The TLS certificate is:
- Signed by a **local Root CA** (EC P-256, generated once by the build script)
- Has an **IP SAN** matching the machine's local IP (auto-detected or passed as argument)
- The same private key and certificate are used by the SPI to sign JAR requests (`x509_hash` scheme)

### PoC Web Application (`poc-webapp/`)

An Express.js application demonstrating end-to-end EUDI authentication. Initiates the OAuth2 PKCE flow, handles the OIDC callback, and displays the authenticated user's credential claims.

### EAA Issuer (external)

A local credential issuer implementing OpenID4VCI that issues PID and Diploma SD-JWT credentials to the EUDI Android Wallet. Runs separately (see `eaa-issuer/`). Exposes a revocation endpoint (`/revocation-list`) following the Token Status List specification.

---

## Authentication Flow

```
Browser                  Keycloak SPI              EUDI Wallet
   │                          │                          │
   │── GET /login ───────────►│                          │
   │                          │ generate nonce, state    │
   │◄── QR Code (deeplink) ───│                          │
   │    openid4vp://?         │                          │
   │    client_id=x509_hash:..│                          │
   │    &request_uri=...      │                          │
   │                          │                          │
   │   [user scans QR] ─────────────────────────────────►│
   │                          │◄── GET /request/{id} ────│
   │                          │─── Signed JAR (ES256) ──►│
   │                          │    (x5c: server+CA cert) │
   │                          │                          │
   │                          │◄── GET /jwks ────────────│
   │                          │─── Public EC Key ───────►│
   │                          │                          │
   │  [polling /status] ─────►│      [user approves]     │
   │                          │◄── POST /callback ───────│
   │                          │    (SD-JWT~disc~KB-JWT)  │
   │                          │                          │
   │                          │ validate VP token:       │
   │                          │  ∙ signature (x5c/JWKS)  │
   │                          │  ∙ SD-JWT _sd hashes     │
   │                          │  ∙ KB-JWT nonce/aud/iat  │
   │                          │  ∙ revocation status     │
   │                          │                          │
   │                          │ provision/update user    │
   │◄── redirect (OIDC) ──────│                          │
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker Desktop | Latest |
| Java JDK | 17+ |
| Maven | 3.8+ (or use included `mvnw`) |
| Node.js | 18+ |
| openssl | Available in PATH |
| EUDI Android Wallet | Built from source (reference app) |

The wallet and the machine running Keycloak must be on the **same LAN**.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/dariapascu/eudi-wallet-keycloak-spi.git
cd eudi-wallet-keycloak-spi
```

### 2. Configure environment variables

```bash
cd keycloak-eudi-project
cp .env.example .env
```

Edit `.env` if needed. Most values are set automatically by the build script. 


### 3. Build and deploy the SPI

```bash
chmod +x build-and-deploy.sh

# Auto-detect local IP:
./build-and-deploy.sh

# Or provide IP explicitly (recommended):
./build-and-deploy.sh x.x.x.x
```

This script:
1. Builds the SPI JAR with Maven (`keycloak-eudi-verifier-1.0.0.jar`)
2. Copies it to `keycloak/providers/`
3. Detects or uses the provided local IP
4. Generates **Root CA EC P-256** (once — skipped if already exists)
5. Copies Root CA to the wallet's raw resources (`eudi_verifier_ca.crt`)
6. Generates **server certificate EC P-256** with IP SAN, signed by the Root CA (regenerated on IP change)
7. Computes the SHA-256 hash of the server certificate (for `client_id` in `x509_hash` scheme)
8. Writes `EUDI_VERIFIER_BASE_URL` and `EUDI_CLIENT_ID` to `.env`
9. Restarts the `keycloak` and `nginx` Docker containers
10. Waits for Keycloak to become healthy

### 4. Windows Firewall (one-time, run as Administrator in PowerShell)

```powershell
netsh advfirewall firewall add rule name="WSL2-nginx-8443" dir=in action=allow protocol=TCP localport=8443
```

Required so that the phone (on LAN) can reach nginx in WSL2.

### 5. Configure Keycloak

Once Keycloak is running at `http://localhost:9080`:

1. Open Admin Console → select realm `auth-realm`
2. **Authentication → Flows** → add execution: **EUDI Wallet Verifier (OpenID4VP)** → set **Required**
3. Create an OIDC client for the PoC webapp:
   - Client ID: `test-app`
   - Valid redirect URIs: `http://localhost:3000/callback`



### 6. Set up the PoC web application

```bash
cd poc-webapp
```

Create `poc-webapp/.env`:

```env
KEYCLOAK_URL=http://localhost:9080
KEYCLOAK_REALM=auth-realm
CLIENT_ID=test-app
CLIENT_SECRET=<your_client_secret>
PORT=3000
SESSION_SECRET=<random_string>
APP_HOST=localhost
REDIRECT_URI=http://localhost:3000/callback
NODE_ENV=development
```

```bash
npm install
npm run dev
```

The application is available at `http://localhost:3000`.

---

## Configuration

### SPI Authenticator Properties

Configured in Keycloak Admin UI under the custom authentication flow (⚙️ on the execution):

| Property | Default | Description |
|---|---|---|
| `pid_vct` | `urn:eu.europa.ec.eudi:pid:1` | Expected `vct` claim for PID credentials |
| `diploma_vct` | `urn:org:certsign:university:graduation:1` | Expected `vct` claim for Diploma credentials |
| `state_timeout_minutes` | `10` | QR code validity timeout |
| `kb_jwt_max_age_seconds` | `300` | Maximum age of KB-JWT from wallet |

### Credential Type Selection

Pass `acr_values` in the OAuth2 authorization request:

```
?acr_values=credential_type:diploma   # request diploma
?acr_values=credential_type:pid       # request PID (default)
```

### Requested Claims (DCQL)

**PID credential:** `given_name`, `family_name`, `birth_date`, `birth_place`

**Diploma credential:** `given_name`, `family_name`, `student_id`, `university`, `graduation_year`, `is_student`, `issuing_country`, `issuance_date`, `expiry_date`

### User Provisioning

Authenticated users are provisioned in Keycloak with namespaced attributes:

| Credential | Keycloak Attribute | Claim |
|---|---|---|
| PID | `pid_given_name` | `given_name` |
| PID | `pid_family_name` | `family_name` |
| PID | `pid_birth_date` | `birth_date` |
| PID | `pid_birth_place` | `birth_place` |
| Diploma | `diploma_student_id` | `student_id` |
| Diploma | `diploma_university` | `university` |
| Diploma | `diploma_graduation_year` | `graduation_year` |
| Diploma | `diploma_is_student` | `is_student` |

Both credential types can be linked to the same Keycloak user account. `firstName` and `lastName` are set exclusively from PID — the authoritative identity source.

---

## Project Structure

```
.
├── keycloak-eudi-project/
│   ├── eudi-verifier/              # Keycloak SPI — Maven Java project
│   │   └── src/main/java/com/license/eudi/
│   │       ├── EudiVerifierAuthenticator.java
│   │       ├── EudiVerifierAuthenticatorFactory.java
│   │       ├── jwt/
│   │       │   ├── RequestObjectJwtBuilder.java
│   │       │   └── VpTokenValidator.java
│   │       ├── openid4vp/
│   │       │   ├── PresentationDefinitionBuilder.java
│   │       │   ├── RequestObjectManager.java
│   │       │   ├── RequestObjectResource.java
│   │       │   └── RequestObjectResourceProviderFactory.java
│   │       ├── resource/
│   │       │   ├── EudiVerifierResource.java
│   │       │   ├── EudiVerifierResourceProvider.java
│   │       │   └── EudiVerifierResourceProviderFactory.java
│   │       └── session/
│   │           └── SessionStateManager.java
│   ├── nginx/
│   │   └── conf.d/                 # nginx reverse proxy config
│   ├── keycloak/
│   │   └── providers/              # Deployed SPI JAR (generated by build script)
│   ├── docker-compose.yml
│   ├── build-and-deploy.sh
│   └── .env.example
└── poc-webapp/                     # Express.js demo application
    ├── server.js
    └── public/
        ├── index.html
        ├── dashboard.html
        └── profile.html
```

---

## Certificate Infrastructure

The system uses a **local PKI** to eliminate the need for external tunnels:

```
Root CA (EC P-256)               — generated once, permanent
    └── Server Cert (EC P-256)   — IP SAN = local IP, regenerated on IP change
          └── signed by Root CA
```

- **Root CA**: installed in the wallet (`raw/eudi_verifier_ca.crt`) — enables HTTPS validation without warnings
- **Server cert**: used by nginx for TLS and by the SPI for signing JARs (`x5c` header)
- **Same private key** for TLS and JAR signing → wallet verifies verifier identity via `x509_hash`

Changing the IP only requires regenerating the server certificate (done automatically by the build script). **The wallet does not need to be rebuilt** unless the Root CA changes.

---

## Standards and Specifications

- [OpenID for Verifiable Presentations (OpenID4VP) — Draft 23+](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SD-JWT — RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)
- [JWT Secured Authorization Request (JAR) — RFC 9101](https://www.rfc-editor.org/rfc/rfc9101)
- [Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6)
- [Token Status List](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.txt)
- [EU Digital Identity Architecture Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [eudi-lib-android-wallet-core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core)
- [eudi-lib-jvm-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt)
