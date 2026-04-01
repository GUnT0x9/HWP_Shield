#!/bin/bash
# HWPShield startup script - runs both backend and frontend

echo "Starting HWPShield..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 is not installed${NC}"
    exit 1
fi

# Check if Node/npm is available
if ! command -v npm &> /dev/null; then
    echo -e "${RED}Error: npm is not installed${NC}"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup INT TERM

cd "$(dirname "$0")"

# Start backend
echo -e "${GREEN}Starting backend (http://localhost:8000)...${NC}"
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -q fastapi uvicorn python-multipart pydantic olefile PyJWT 2>/dev/null || true

# Start backend server
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
cd ..

# Wait for backend to start
echo "Waiting for backend to start..."
sleep 3

# Check if backend is running
if ! curl -s http://localhost:8000/api/health > /dev/null; then
    echo -e "${RED}Warning: Backend may not have started correctly${NC}"
else
    echo -e "${GREEN}Backend is running!${NC}"
fi

# Start frontend
echo -e "${GREEN}Starting frontend (http://localhost:3000)...${NC}"
cd frontend

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Start frontend dev server
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo -e "${GREEN}HWPShield is running!${NC}"
echo "Frontend: http://localhost:3000"
echo "API: http://localhost:8000/api"
echo "API Docs: http://localhost:8000/api/docs"
echo ""
echo "Press Ctrl+C to stop"

# Wait for both processes
wait
