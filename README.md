# Keycloak EUDI Wallet Verifier — OpenID4VP SPI

A Keycloak **Service Provider Interface (SPI)** that enables user authentication via the **EUDI Android Wallet** using the **OpenID for Verifiable Presentations (OpenID4VP)** protocol. Users present a verifiable credential (Government-issued PID or University Diploma) from their digital wallet and are automatically provisioned and authenticated into Keycloak.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   ┌─────────────────┐   OpenID4VP    ┌──────────────────────────────┐    │
│   │  EUDI Android   │◄──────────────►│  Keycloak 26 + Verifier SPI  │    │
│   │    Wallet       │                │                              │    │
│   │                 │                │                              │    │
│   │  ∙ PID          │                │  ∙ Custom Auth Flow          │    │
│   │  ∙ Diploma      │                │  ∙ JAR Request Object        │    │
│   └────────┬────────┘                │  ∙ VP Token Validation       │    │
│            │                         │  ∙ User Provisioning         │    │
│            │ OpenID4VCI              └──────────────┬───────────────┘    │
│            │ (credential issuance)                  │ OIDC / OAuth2      │
│   ┌────────▼────────┐                ┌──────────────▼──────────────┐     │
│   │   EAA Issuer    │                │     PoC Web Application     │     │
│   │  (local server) │                │                             │     │
│   │                 │                │                             │     │
│   │  ∙ Issues PID   │                │  ∙ QR Code display          │     │
│   │  ∙ Issues Dipl. │                │  ∙ Auth status polling      │     │
│   └─────────────────┘                │  ∙ Profile page             │     │
│                                      └─────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────────┘
```

The browser and EUDI Wallet run on separate devices. The wallet communicates with Keycloak over the internet via an **ngrok tunnel**, while the browser polls for authentication completion.

---

## Components

### Keycloak EUDI Verifier SPI (`keycloak-eudi-project/eudi-verifier/`)

A Java SPI plugin for Keycloak 26 that implements the OpenID4VP verification flow. Packaged as a JAR and deployed into Keycloak's `providers/` directory.

| Class | Responsibility |
|---|---|
| `EudiVerifierAuthenticator` | Core authenticator — orchestrates the full OpenID4VP flow |
| `EudiVerifierAuthenticatorFactory` | Registers the authenticator and its configuration properties |
| `RequestObjectJwtBuilder` | Builds signed JAR (JWT Secured Authorization Request) using ES256 |
| `VpTokenValidator` | Validates VP Token: signature (x5c / JWKS), SD-JWT disclosures, KB-JWT |
| `PresentationDefinitionBuilder` | Generates DCQL queries for PID and Diploma credentials |
| `RequestObjectManager` | Stores and serves Request Objects by reference (5-min expiry) |
| `RequestObjectResource` | REST endpoints: `GET /request/{id}`, `POST /callback` |
| `SessionStateManager` | Maps OAuth2 `state` to Keycloak auth sessions (10-min timeout) |

### PoC Web Application (`poc-webapp/`)

An Express.js application demonstrating end-to-end EUDI authentication. Initiates the OAuth2 PKCE flow, handles the OIDC callback, and displays the authenticated user's credential claims.

### EAA Issuer (external)

A local credential issuer implementing OpenID4VCI that issues PID and Diploma SD-JWT credentials to the EUDI Android Wallet. Runs separately.

---

## Authentication Flow

```
Browser                  Keycloak SPI              EUDI Wallet
   │                          │                         │
   │── GET /login ───────────►│                         │
   │                          │ generate nonce, state   │
   │◄── QR Code (deeplink) ───│                         │
   │                          │                         │
   │   [user scans QR] ────────────────────────────────►│
   │                          │◄── GET /request/{id} ───│
   │                          │─── Request Object ─────►│
   │                          │    (JAR, ES256 signed)  │
   │                          │                         │
   │                          │   [wallet builds VP]    │
   │                          │◄── POST /callback ──────│
   │                          │    (SD-JWT + KB-JWT)    │
   │                          │                         │
   │                          │ validate VP token:      │
   │                          │  ∙ signature (x5c)      │
   │                          │  ∙ SD-JWT _sd hashes    │
   │                          │  ∙ KB-JWT nonce/aud/iat │
   │                          │                         │
   │                          │ provision/update user   │
   │◄── redirect (OIDC) ──────│                         │
   │                          │                         │
```

The PoC web application displays a QR code encoding the `openid4vp://` deep link. The user scans it with the EUDI Android Wallet, which natively handles the URI scheme and initiates the presentation flow.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker Desktop | Latest |
| Java JDK | 17+ |
| Maven | 3.8+ (or use included `mvnw`) |
| Node.js | 18+ |
| ngrok | Latest |
| EUDI Android Wallet | Built from source (reference app) |


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

Edit `.env`:

```env
EUDI_VERIFIER_BASE_URL=https://<your-ngrok-url>.ngrok-free.app
KC_ADMIN_USERNAME=admin
KC_ADMIN_PASSWORD=your_password
```

> `EUDI_VERIFIER_BASE_URL` is updated automatically by `build-and-deploy.sh` when ngrok starts. You can leave it empty on first run.

### 3. Set up ngrok

The EUDI Android Wallet communicates with Keycloak over the internet. ngrok creates a public HTTPS tunnel to your local Keycloak instance.

**Install ngrok:**
```bash
# Linux / WSL2
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok
```

**Authenticate ngrok** (one-time setup — requires a free account at [ngrok.com](https://ngrok.com)):
```bash
ngrok config add-authtoken <your_authtoken>
```

> The authtoken is found in your ngrok dashboard under *Your Authtoken*. Without it, ngrok will refuse to start tunnels.

The `build-and-deploy.sh` script starts the tunnel automatically on port 9080 and writes the public URL to `.env`. You do not need to start ngrok manually.


### 4. Build and deploy the SPI

```bash
chmod +x build-and-deploy.sh
./build-and-deploy.sh
```

This script:
1. Builds the SPI JAR with Maven (`keycloak-eudi-verifier-1.0.0.jar`)
2. Copies it to `keycloak/providers/`
3. Starts an ngrok tunnel on port 9080
4. Updates `EUDI_VERIFIER_BASE_URL` in `.env` with the live ngrok URL
5. Starts the Keycloak Docker container
6. Waits for Keycloak to become healthy

### 4. Configure Keycloak

Once Keycloak is running at `http://localhost:9080`:

1. **Import or recreate the realm** — a pre-configured H2 database is included in `keycloak/data/`. If starting fresh, create a realm and configure the EUDI authentication flow manually.

2. **Create an OIDC client** for the PoC webapp:
   - Client ID: `test-app`
   - Valid redirect URIs: `http://localhost:3000/callback`
   - Note the generated client secret.

3. **Add attribute mappers** (maps wallet claims to ID token):

```bash
cd ..
pip install requests
python setup_keycloak_mappers.py
```

### 5. Set up the PoC web application

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

Install dependencies and start:

```bash
npm install
npm run dev
```

The application is available at `http://localhost:3000`.

---

## Configuration

### SPI Authenticator Properties

Configured in Keycloak Admin UI under the custom authentication flow:

| Property | Default | Description |
|---|---|---|
| `eudi_verifier_base_url` | (from env) | Public base URL exposed via ngrok |
| `pid_vct` | `urn:eu.europa.ec.eudi:pid:1` | Expected `vct` claim for PID credentials |
| `diploma_vct` | `urn:org:certsign:university:graduation:1` | Expected `vct` claim for Diploma credentials |
| `kb_jwt_max_age_ms` | `300000` (5 min) | Maximum age of KB-JWT |

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

Both credential types can be linked to the same Keycloak user account.

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
│   ├── keycloak/
│   │   ├── data/                   # Persistent Keycloak H2 database
│   │   └── providers/              # Deployed SPI JAR (generated)
│   ├── docker-compose.yml
│   ├── build-and-deploy.sh
│   └── .env.example
├── poc-webapp/                     # Express.js demo application
    ├── server.js
    └── public/
        ├── index.html
        ├── dashboard.html
        └── profile.html

```

---

## Standards and Specifications

- [OpenID for Verifiable Presentations (OpenID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SD-JWT — Selective Disclosure for JWTs](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.txt)
- [JWT Secured Authorization Request (JAR) — RFC 9101](https://www.rfc-editor.org/rfc/rfc9101)
- [Digital Credentials Query Language (DCQL)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6)
- [EU Digital Identity Architecture Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
