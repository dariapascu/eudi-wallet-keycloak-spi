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

echo -e "${YELLOW}📁 Working directory: $PROJECT_DIR${NC}"
echo ""

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

# Step 4: Create providers directory if it doesn't exist
echo -e "${YELLOW}📂 Step 3: Preparing providers directory...${NC}"
mkdir -p "$KEYCLOAK_PROVIDERS_DIR"
echo -e "${GREEN}✅ Providers directory ready: $KEYCLOAK_PROVIDERS_DIR${NC}"
echo ""

# Step 5: Copy JAR to providers directory
echo -e "${YELLOW}📦 Step 4: Copying JAR to Keycloak providers...${NC}"
cp "$JAR_FILE" "$KEYCLOAK_PROVIDERS_DIR/"
echo -e "${GREEN}✅ JAR copied successfully${NC}"
echo ""

# Step 6: Kill any existing ngrok and start fresh on correct port
echo -e "${YELLOW}🌐 Step 5: Restarting ngrok tunnel on port 9080...${NC}"
echo "Killing any existing ngrok processes..."
pkill -f ngrok 2>/dev/null || true
sleep 2
echo "Starting ngrok in background on port 9080..."
nohup ngrok http 9080 > "$PROJECT_DIR/ngrok.log" 2>&1 &
echo "Waiting for ngrok to initialize..."
sleep 5
echo -e "${GREEN}✅ ngrok tunnel started on port 9080${NC}"

# Get ngrok URL
NGROK_URL=""
for i in {1..10}; do
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*' | head -1)
    if [ -n "$NGROK_URL" ]; then
        break
    fi
    echo "Waiting for ngrok API... ($i/10)"
    sleep 2
done

if [ -z "$NGROK_URL" ]; then
    echo -e "${RED}❌ Failed to get ngrok URL${NC}"
    echo "Check ngrok.log for details"
    exit 1
fi

echo -e "${GREEN}✅ ngrok public URL: $NGROK_URL${NC}"
echo ""

# Write ngrok URL to .env file 
echo -e "${YELLOW}📝 Writing ngrok URL to .env file...${NC}"
ENV_FILE="$PROJECT_DIR/.env"
if [ -f "$ENV_FILE" ]; then
    sed -i '/^EUDI_VERIFIER_BASE_URL=/d' "$ENV_FILE"
fi
echo "EUDI_VERIFIER_BASE_URL=$NGROK_URL" >> "$ENV_FILE"
echo -e "${GREEN}✅ Set EUDI_VERIFIER_BASE_URL=$NGROK_URL in .env${NC}"
echo ""

# Step 7: Restart Keycloak (Docker)
echo -e "${YELLOW}🔄 Step 6: Restarting Keycloak container...${NC}"
cd "$PROJECT_DIR"

if docker-compose ps | grep -q "keycloak"; then
    echo "Stopping Keycloak..."
    docker-compose stop keycloak
    echo "Starting Keycloak..."
    docker-compose up -d keycloak
    echo -e "${GREEN}✅ Keycloak restarted${NC}"
else
    echo -e "${YELLOW}⚠️  Keycloak container not found. Starting it...${NC}"
    docker-compose up -d keycloak
    echo -e "${GREEN}✅ Keycloak started${NC}"
fi
echo ""

# Step 8: Wait for Keycloak to be ready
echo -e "${YELLOW}⏳ Step 7: Waiting for Keycloak to be ready...${NC}"
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

# Step 8: Display success message
echo ""
echo "=========================================="
echo -e "${GREEN}✅ DEPLOYMENT SUCCESSFUL!${NC}"
echo "=========================================="
echo ""
echo "📋 Next steps:"
echo "1. Open Keycloak Admin Console: http://localhost:8080"
echo "2. Login with admin/admin"
echo "3. Go to your realm → Authentication → Flows"
echo "4. Create/Edit a Browser Flow and add 'EUDI Wallet Verifier (OpenID4VP)'"
echo "5. Test the authentication with a client application"
echo ""
echo "📊 Useful commands:"
echo "   - Check Keycloak logs: docker logs -f keycloak-eudi-project-keycloak-1"
echo "   - Check ngrok status: curl http://localhost:4040/api/tunnels"
echo "   - ngrok Web UI: http://localhost:4040"
echo ""
