#!/bin/bash
apt-get update
apt-get install -y python3-pip git

# Simulate a hardcoded AWS key (⚠️ insecure)
echo "AWS_ACCESS_KEY_ID=AKIAXXXXXEXPOSED" >> /etc/environment
echo "AWS_SECRET_ACCESS_KEY=SECRETEXPOSEDKEYHERE" >> /etc/environment

git clone https://github.com/your-org/vulnerable-flask-app.git /app
cd /app
pip3 install -r requirements.txt
python3 app.py
