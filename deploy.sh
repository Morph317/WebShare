#!/bin/bash
set -e

echo "=== WebShare Deploy ==="

# Check if ANNOUNCED_IP is set
if [ -z "$ANNOUNCED_IP" ]; then
  echo "Usage: ANNOUNCED_IP=<your-public-ip> ./deploy.sh"
  exit 1
fi

echo "Announced IP: $ANNOUNCED_IP"

# Install dependencies
echo ""
echo ">>> Installing server dependencies..."
cd server && npm install && cd ..

echo ""
echo ">>> Installing client dependencies..."
cd client && npm install && cd ..

# Build
echo ""
echo ">>> Building client..."
cd client && npm run build && cd ..

echo ""
echo ">>> Building server..."
cd server && npm run build && cd ..

# Stop old process if running
OLD_PID=$(pgrep -f "node dist/index.js" 2>/dev/null || true)
if [ -n "$OLD_PID" ]; then
  echo ""
  echo ">>> Stopping old server (PID: $OLD_PID)..."
  kill $OLD_PID 2>/dev/null || true
  sleep 2
fi

# Start server
echo ""
echo ">>> Starting server..."
cd server
ANNOUNCED_IP=$ANNOUNCED_IP node dist/index.js
