#!/bin/bash
read -p "Vrei să te conectezi prin SSH la GitHub? (y/n): " use_ssh

if [[ "$use_ssh" == "y" ]]; then
    ssh -T git@github.com

    git remote set-url origin git@github.com:antonndev/adpanel.git
fi

git init
git add .

git commit -m "ADPanel Update"

git push --set-upstream origin main