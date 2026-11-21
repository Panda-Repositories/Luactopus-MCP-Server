@echo off
echo Project Radium Railway commands
echo.
echo 1. railway login
echo 2. railway init --name project-radium
echo 3. railway add --service radium-deobf
echo 4. railway variable set BOT_TOKEN="YOUR_TOKEN" DATA_DIR=/data LUNE_PATH=/usr/local/bin/lune LUA=lua5.4 -s radium-deobf
echo 5. railway volume add --mount-path /data -s radium-deobf
echo 6. railway up --service radium-deobf
echo 7. railway service logs --service radium-deobf
