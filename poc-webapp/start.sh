#!/bin/bash

echo "=========================================="
echo "🚀 EUDI Wallet PoC - Starting Server"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found!"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo ""
    echo "❗ IMPORTANT: Please edit .env and configure:"
    echo "   - CLIENT_SECRET (from Keycloak)"
    echo "   - SESSION_SECRET (random string)"
    echo "   - KEYCLOAK_REALM (your realm name)"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Check if Keycloak is running
echo "🔍 Checking if Keycloak is running..."
if curl -s -f http://localhost:9080/realms/master > /dev/null 2>&1; then
    echo "✅ Keycloak is running"
else
    echo "❌ Keycloak is not running on http://localhost:9080"
    echo ""
    echo "Please start Keycloak first:"
    echo "  cd ../keycloak-eudi-project"
    echo "  docker-compose up -d"
    exit 1
fi

# Check if ngrok is running
echo "🔍 Checking if ngrok is running..."
if curl -s http://localhost:4040/api/tunnels > /dev/null 2>&1; then
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels 2>/dev/null | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*' | head -1)
    echo "✅ ngrok is running: $NGROK_URL"
else
    echo "⚠️  ngrok is not running"
    echo "   This is needed for mobile wallet access"
    echo "   Start it with: cd ../keycloak-eudi-project && ./build-and-deploy.sh"
fi

echo ""

# Check if node_modules exists
if [ ! -d node_modules ]; then
    echo "❌ node_modules not found!"
    echo "   Run 'npm install' from Windows PowerShell in this directory:"
    echo "   cd \"D:\\ATM\\Anul 4\\Licenta\\PracticAndroid\\poc-webapp\""
    echo "   npm install"
    exit 1
fi

# Start the server
echo "🚀 Starting Node.js server..."
echo ""
"/mnt/c/Program Files/nodejs/node.exe" server.js
