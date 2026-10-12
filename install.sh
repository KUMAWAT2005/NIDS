#!/bin/bash
set -e

# NIDS project directory
PROJECT_DIR="/home/ritesh/Desktop/NIDS"

# Clone the repository if it does not exist
if [ ! -d "$PROJECT_DIR/.git" ]; then
    git clone https://github.com/KUMAWAT2005/NIDS "$PROJECT_DIR"
fi

cd "$PROJECT_DIR"

# Create the virtual environment first
python3 -m venv venv

# Install dependencies inside the virtual environment
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt

# Create the log file
mkdir -p logs
touch logs/nids_alerts.log

# Run the NIDS packet sniffer with root privileges
sudo ./venv/bin/python packet_sniffer.py
