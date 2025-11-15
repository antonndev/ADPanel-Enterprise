#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[1;35m'
NC='\033[0m'

echo -e "${MAGENTA}==============================${NC}"
echo -e "${CYAN} Welcome to ADPanel Initializer ${NC}"
echo -e "${MAGENTA}==============================${NC}"

echo -e "${YELLOW}Choose an option:${NC}"
echo -e "1) Initialize Panel"
echo -e "2) Change Admin Password"
echo -e "3) Delete Admin User"
echo -e "4) Create User"
read -p "Enter choice (1, 2, 3 or 4): " CHOICE

USER_FILE="./user.json"

install_dependencies() {
  echo -e "${CYAN}Installing dependencies...${NC}"
  npm install adm-zip express-session speakeasy qrcode bcryptjs express-rate-limit qrcode-terminal tar bcrypt
}

BCRYPT_CODE="
let bcrypt;
try { bcrypt = require('bcrypt'); } catch (e) { 
  console.log('Using bcryptjs fallback'); 
  bcrypt = require('bcryptjs'); 
}
module.exports = bcrypt;
"

change_password() {
  if [ ! -f "$USER_FILE" ]; then
    echo -e "${RED}Admin user not found! Initialize the panel first.${NC}"
    exit 1
  fi

  ATTEMPTS=3
  while [ $ATTEMPTS -gt 0 ]; do
    read -s -p "Enter current password: " CURRENT
    echo ""
    VALID=$(node -e "
      const fs = require('fs');
      const bcrypt = require('bcryptjs');
      const user = JSON.parse(fs.readFileSync('$USER_FILE'))[0];
      console.log(bcrypt.compareSync('$CURRENT', user.password));
    ")
    if [ "$VALID" == "true" ]; then
      break
    else
      ATTEMPTS=$((ATTEMPTS-1))
      echo -e "${RED}Incorrect password. Remaining attempts: $ATTEMPTS${NC}"
      if [ $ATTEMPTS -eq 0 ]; then
        echo -e "${RED}Too many failed attempts. Exiting.${NC}"
        exit 1
      fi
    fi
  done

  while true; do
    read -s -p "Enter new password: " NEW1
    echo ""
    read -s -p "Confirm new password: " NEW2
    echo ""
    if [ "$NEW1" != "$NEW2" ]; then
      echo -e "${RED}Passwords do not match. Try again.${NC}"
    else
      break
    fi
  done

  HASH=$(node -e "
    const bcrypt = require('bcryptjs');
    console.log(bcrypt.hashSync('$NEW1', 10));
  ")
  node -e "
    const fs = require('fs');
    const user = JSON.parse(fs.readFileSync('$USER_FILE'));
    user[0].password = '$HASH';
    fs.writeFileSync('$USER_FILE', JSON.stringify(user, null, 2));
  "

  echo -e "${GREEN}Password changed successfully!${NC}"
  echo -e "${YELLOW}Please restart the panel for changes to take effect.${NC}"
}

delete_user() {
  if [ ! -f "$USER_FILE" ]; then
    echo -e "${RED}No admin user found to delete.${NC}"
    exit 1
  fi

  ATTEMPTS=3
  while [ $ATTEMPTS -gt 0 ]; do
    read -s -p "Enter current password to confirm deletion: " CURRENT
    echo ""
    VALID=$(node -e "
      const fs = require('fs');
      const bcrypt = require('bcryptjs');
      const user = JSON.parse(fs.readFileSync('$USER_FILE'))[0];
      console.log(bcrypt.compareSync('$CURRENT', user.password));
    ")
    if [ "$VALID" == "true" ]; then
      rm -f "$USER_FILE"
      echo -e "${GREEN}Admin user deleted successfully!${NC}"
      exit 0
    else
      ATTEMPTS=$((ATTEMPTS-1))
      echo -e "${RED}Incorrect password. Remaining attempts: $ATTEMPTS${NC}"
      if [ $ATTEMPTS -eq 0 ]; then
        echo -e "${RED}Too many failed attempts. Exiting.${NC}"
        exit 1
      fi
    fi
  done
}

initialize_panel() {
  echo -e "${CYAN}=== Panel Initialization ===${NC}"

  read -p "Enter admin email: " EMAIL
  read -s -p "Enter admin password: " PASSWORD
  echo ""

  install_dependencies

  SECRET=$(node -e "
    const speakeasy = require('speakeasy');
    console.log(speakeasy.generateSecret({length: 20}).base32);
  ")
  echo -e "${YELLOW}Your 2FA secret (manual entry works too):${NC} $SECRET"

  echo -e "${CYAN}Scan this QR code in your Authenticator app:${NC}"
  node -e "
    const speakeasy = require('speakeasy');
    const qrcode = require('qrcode-terminal');
    const otpAuth = speakeasy.otpauthURL({
      secret: '$SECRET',
      label: '$EMAIL',
      issuer: 'ADPanel',
      encoding: 'base32'
    });
    qrcode.generate(otpAuth, { small: true });
  "

  HASH=$(node -e "
    const bcrypt = require('bcryptjs');
    console.log(bcrypt.hashSync('$PASSWORD', 10));
  ")

  cat <<EOF > "$USER_FILE"
[
  {
    "email": "$EMAIL",
    "password": "$HASH",
    "secret": "$SECRET",
    "admin": true
  }
]
EOF

  echo -e "${GREEN}Admin account created and saved in user.json${NC}"
  echo -e "${YELLOW}Panel setup complete!${NC}"
  echo -e "${CYAN}Starting panel in background...${NC}"
  nohup node panel.js > /dev/null 2>&1 &
  echo -e "${GREEN}Panel running.${NC}"
}

create_user() {
  echo -e "${CYAN}=== Create New User ===${NC}"

  read -p "Enter user email: " EMAIL
  while true; do
    read -s -p "Enter user password: " PASS1
    echo ""
    read -s -p "Confirm user password: " PASS2
    echo ""
    if [ "$PASS1" != "$PASS2" ]; then
      echo -e "${RED}Passwords do not match. Try again.${NC}"
    else
      break
    fi
  done

  read -p "Should this user be an admin? (y/n, just for info): " ISADMIN

  SECRET=$(node -e "
    const speakeasy = require('speakeasy');
    console.log(speakeasy.generateSecret({length: 20}).base32);
  ")
  echo -e "${YELLOW}Your 2FA secret (manual entry works too):${NC} $SECRET"

  echo -e "${CYAN}Scan this QR code in your Authenticator app:${NC}"
  node -e "
    const speakeasy = require('speakeasy');
    const qrcode = require('qrcode-terminal');
    const otpAuth = speakeasy.otpauthURL({
      secret: '$SECRET',
      label: '$EMAIL',
      issuer: 'ADPanel',
      encoding: 'base32'
    });
    qrcode.generate(otpAuth, { small: true });
  "

  HASH=$(node -e "
    const bcrypt = require('bcryptjs');
    console.log(bcrypt.hashSync('$PASS1', 10));
  ")

  node -e "
    const fs = require('fs');
    const path = '$USER_FILE';
    const email = '$EMAIL';
    const password = '$HASH';
    const secret = '$SECRET';
    const isAdmin = String('$ISADMIN').toLowerCase().startsWith('y');
    let data = [];
    if (fs.existsSync(path)) {
      try {
        const content = fs.readFileSync(path,'utf8');
        const parsed = JSON.parse(content);
        if (Array.isArray(parsed)) data = parsed;
        else if (typeof parsed === 'object' && parsed !== null) data = [parsed];
      } catch(e) {
        data = [];
      }
    }
    data.push({ email, password, secret, admin: isAdmin });
    fs.writeFileSync(path, JSON.stringify(data, null, 2));
  "

  echo -e "${GREEN}User created successfully! Take your journey!${NC}"
}

if [ "$CHOICE" == "1" ]; then
  initialize_panel
elif [ "$CHOICE" == "2" ]; then
  change_password
elif [ "$CHOICE" == "3" ]; then
  delete_user
elif [ "$CHOICE" == "4" ]; then
  create_user
else
  echo -e "${RED}Invalid choice. Exiting.${NC}"
  exit 1
fi
