#!/bin/bash

set -e

echo "=========================================="
echo "EUDI Verifier - Build și Deploy"
echo "=========================================="
echo ""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFIER_DIR="$PROJECT_DIR/eudi-verifier"
KEYCLOAK_PROVIDERS_DIR="$PROJECT_DIR/keycloak/providers"
CA_DIR="$PROJECT_DIR/nginx/ca"
CERTS_DIR="$PROJECT_DIR/nginx/certs"
WALLET_RAW_DIR="/mnt/d/ATM/Anul 4/Licenta/LeancaAndroid/eudi-app-android-wallet-ui/resources-logic/src/main/res/raw"

echo -e "${YELLOW}📁 Working directory: $PROJECT_DIR${NC}"
echo ""

# IP-ul poate fi dat ca parametru: ./build-and-deploy.sh 192.168.1.100
LOCAL_IP="$1"

# Step 1: Clean previous build
echo -e "${YELLOW}🧹 Step 1: Cleaning previous build...${NC}"
cd "$VERIFIER_DIR"
./mvnw clean
echo -e "${GREEN}✅ Clean completed${NC}"
echo ""

# Step 2: Build JAR
echo -e "${YELLOW}🔨 Step 2: Building JAR with Maven...${NC}"
./mvnw package -DskipTests
echo -e "${GREEN}✅ Build completed${NC}"
echo ""

# Step 3: Check if JAR exists
JAR_FILE="$VERIFIER_DIR/target/keycloak-eudi-verifier-1.0.0.jar"
if [ ! -f "$JAR_FILE" ]; then
    echo -e "${RED}❌ Error: JAR file not found at $JAR_FILE${NC}"
    exit 1
fi
echo -e "${GREEN}✅ JAR file found: $JAR_FILE${NC}"
echo ""

# Step 4: Copy JAR to providers directory
echo -e "${YELLOW}📂 Step 3: Preparing providers directory...${NC}"
mkdir -p "$KEYCLOAK_PROVIDERS_DIR"
cp "$JAR_FILE" "$KEYCLOAK_PROVIDERS_DIR/"
echo -e "${GREEN}✅ JAR copied to: $KEYCLOAK_PROVIDERS_DIR${NC}"
echo ""

# Step 5: Resolve IP address
echo -e "${YELLOW}🌐 Step 4: Resolving IP address...${NC}"
if [ -n "$LOCAL_IP" ]; then
    echo -e "${GREEN}✅ Using provided IP: $LOCAL_IP${NC}"
else
    echo "No IP provided, attempting auto-detection..."
    if grep -qi microsoft /proc/version 2>/dev/null; then
        LOCAL_IP=$(ipconfig.exe 2>/dev/null \
            | grep -A4 "Wi-Fi" \
            | grep "IPv4" \
            | awk -F': ' '{print $2}' \
            | tr -d '\r' \
            | head -1)
        if [ -z "$LOCAL_IP" ]; then
            LOCAL_IP=$(ipconfig.exe 2>/dev/null \
                | grep -A4 "Ethernet" \
                | grep "IPv4" \
                | awk -F': ' '{print $2}' \
                | tr -d '\r' \
                | head -1)
        fi
    else
        LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
        if [ -z "$LOCAL_IP" ]; then
            LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        fi
    fi

    if [ -z "$LOCAL_IP" ]; then
        echo -e "${RED}❌ Could not detect IP. Pass it explicitly: ./build-and-deploy.sh <IP>${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Auto-detected IP: $LOCAL_IP${NC}"
fi
echo ""

# Step 6: Generate Root CA (once, permanently)
echo -e "${YELLOW}🔐 Step 5: Checking Root CA...${NC}"
mkdir -p "$CA_DIR" "$CERTS_DIR"
WALLET_REBUILD_NEEDED=false


# Detectam daca CA-ul existent e RSA (vechi) — trebuie regenerat ca EC P-256
CA_IS_EC=false
if [ -f "$CA_DIR/ca.crt" ]; then
    openssl x509 -in "$CA_DIR/ca.crt" -text -noout 2>/dev/null | grep -q "id-ecPublicKey" && CA_IS_EC=true
fi

if [ ! -f "$CA_DIR/ca.crt" ] || [ ! -f "$CA_DIR/ca.key" ] || [ "$CA_IS_EC" = false ]; then
    echo "Generating Root CA EC P-256 (first time only)..."
    # EC P-256, format PKCS#8 — compatibil cu Java KeyFactory fara Bouncy Castle
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA_DIR/ca.key" 2>/dev/null
    openssl req -new -x509 -days 3650 \
        -key "$CA_DIR/ca.key" \
        -out "$CA_DIR/ca.crt" \
        -subj "/CN=EUDI Verifier Root CA" 2>/dev/null
    # Stergem si cert-ul server daca exista (trebuie re-semnat cu noul CA)
    rm -f "$CERTS_DIR/server.crt" "$CERTS_DIR/server.key" "$CERTS_DIR/cert-params.txt"
    echo -e "${GREEN}✅ Root CA EC P-256 generated${NC}"
    WALLET_REBUILD_NEEDED=true
else
    echo -e "${GREEN}✅ Root CA already exists (EC P-256)${NC}"
fi

# Copy Root CA to wallet raw resources
if [ "$WALLET_REBUILD_NEEDED" = true ]; then
    if [ -d "$WALLET_RAW_DIR" ]; then
        cp "$CA_DIR/ca.crt" "$WALLET_RAW_DIR/eudi_verifier_ca.crt"
        echo -e "${GREEN}✅ Root CA copied to wallet resources${NC}"
    else
        echo -e "${YELLOW}⚠️  Wallet raw dir not found. Copy manually:${NC}"
        echo "   cp $CA_DIR/ca.crt <wallet>/resources-logic/src/main/res/raw/eudi_verifier_ca.crt"
    fi
    echo ""
    echo -e "${YELLOW}⚠️  ROOT CA CHANGED: rebuild and reinstall the wallet app (once)${NC}"
    echo ""
fi
echo ""

# Step 7: Generate server cert signed by Root CA (if IP changed or cert missing)
echo -e "${YELLOW}🔏 Step 6: Checking server certificate...${NC}"
CERT_PARAMS_FILE="$CERTS_DIR/cert-params.txt"
STORED_IP=""
if [ -f "$CERT_PARAMS_FILE" ]; then
    STORED_IP=$(cat "$CERT_PARAMS_FILE")
fi

# Regenerate daca cert-ul nu e semnat de CA-ul nostru (ex: vechi self-signed)
SIGNED_BY_CA=false
if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CA_DIR/ca.crt" ]; then
    openssl verify -CAfile "$CA_DIR/ca.crt" "$CERTS_DIR/server.crt" > /dev/null 2>&1 && SIGNED_BY_CA=true
fi

if [ ! -f "$CERTS_DIR/server.crt" ] || [ "$LOCAL_IP" != "$STORED_IP" ] || [ "$SIGNED_BY_CA" = false ]; then
    echo "Generating server certificate for IP: $LOCAL_IP (signed by Root CA, EC P-256)..."

    # Server key EC P-256 PKCS#8 — Java il poate citi nativ fara Bouncy Castle
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
        -out "$CERTS_DIR/server.key" 2>/dev/null

    # CSR
    openssl req -new -key "$CERTS_DIR/server.key" -out /tmp/eudi-server.csr \
        -subj "/CN=eudi-verifier" 2>/dev/null

    # SAN: IP SAN pentru TLS — cu X509Hash nu e nevoie de DNS SAN
    cat > /tmp/eudi-server-ext.cnf << EOF
subjectAltName = IP:${LOCAL_IP}
EOF
    openssl x509 -req -days 3650 \
        -in /tmp/eudi-server.csr \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$CERTS_DIR/server.crt" \
        -extfile /tmp/eudi-server-ext.cnf 2>/dev/null

    rm -f /tmp/eudi-server.csr /tmp/eudi-server-ext.cnf
    echo "$LOCAL_IP" > "$CERT_PARAMS_FILE"
    echo -e "${GREEN}✅ Server certificate generated and signed by Root CA${NC}"
else
    echo -e "${GREEN}✅ Server certificate already valid for $LOCAL_IP${NC}"
fi

# Calculeaza hash-ul cert-ului (x509_hash scheme: SHA-256 DER base64url)
CERT_HASH=$(openssl x509 -in "$CERTS_DIR/server.crt" -outform DER \
    | openssl dgst -sha256 -binary \
    | base64 | tr '+/' '-_' | tr -d '=')
echo -e "${GREEN}✅ Cert hash (x509_hash): $CERT_HASH${NC}"
echo ""

# Step 8: Write env vars to .env
echo -e "${YELLOW}📝 Step 7: Writing verifier URL to .env file...${NC}"
NGINX_URL="https://$LOCAL_IP:8443"
ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    grep -v '^EUDI_VERIFIER_BASE_URL=' "$ENV_FILE" \
    | grep -v '^EUDI_CLIENT_ID=' \
    > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
fi
echo "EUDI_VERIFIER_BASE_URL=$NGINX_URL" >> "$ENV_FILE"
echo "EUDI_CLIENT_ID=x509_hash:$CERT_HASH" >> "$ENV_FILE"
echo -e "${GREEN}✅ Set EUDI_VERIFIER_BASE_URL=$NGINX_URL${NC}"
echo -e "${GREEN}✅ Set EUDI_CLIENT_ID=x509_hash:$CERT_HASH${NC}"
echo ""

# Step 9: Restart Keycloak and nginx
echo -e "${YELLOW}🔄 Step 8: Restarting containers...${NC}"
cd "$PROJECT_DIR"
# Folosim 'docker compose' (plugin modern) cu fallback la 'docker-compose' (legacy)
DOCKER_COMPOSE="docker compose"
$DOCKER_COMPOSE version > /dev/null 2>&1 || DOCKER_COMPOSE="docker-compose"

$DOCKER_COMPOSE down --timeout 10 2>/dev/null || true
$DOCKER_COMPOSE up -d keycloak nginx
echo -e "${GREEN}✅ Containers started${NC}"
echo ""

# Step 10: Wait for Keycloak to be ready
echo -e "${YELLOW}⏳ Step 9: Waiting for Keycloak to be ready...${NC}"
echo "This may take 30-60 seconds..."

MAX_ATTEMPTS=60
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    if curl -s -f http://localhost:9080/realms/master > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Keycloak is ready!${NC}"
        break
    fi
    ATTEMPT=$((ATTEMPT + 1))
    echo -n "."
    sleep 2
done

if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
    echo -e "${RED}❌ Timeout waiting for Keycloak to start${NC}"
    exit 1
fi
echo ""

echo ""
echo "=========================================="
echo -e "${GREEN}✅ DEPLOYMENT SUCCESSFUL!${NC}"
echo "=========================================="
echo ""
echo "🌐 Verifier public URL: $NGINX_URL"
echo "🔑 Client ID (x509_hash): x509_hash:$CERT_HASH"
echo ""
echo "📋 Next steps:"
echo "1. Open Keycloak Admin Console: http://localhost:9080/admin"
if [ "$WALLET_REBUILD_NEEDED" = true ]; then
echo ""
echo -e "${YELLOW}⚠️  Rebuild and reinstall the wallet app (Root CA was updated)${NC}"
fi
echo ""
echo "📊 Useful commands:"
echo "   - Keycloak logs: $DOCKER_COMPOSE logs -f keycloak"
echo "   - nginx logs:    $DOCKER_COMPOSE logs -f nginx"
echo "   - Test nginx:    curl -k $NGINX_URL/realms/master  (port 8443)"
echo ""
echo -e "${YELLOW}⚠️  First-time Windows Firewall setup (run once as Administrator in PowerShell):${NC}"
echo '   netsh advfirewall firewall add rule name="WSL2-nginx-8443" dir=in action=allow protocol=TCP localport=8443'
echo ""
