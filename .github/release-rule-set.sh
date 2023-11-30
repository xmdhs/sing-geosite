#!/bin/bash

set -e -o pipefail

cd $1
git init
git config --local user.email "github-action@users.noreply.github.com"
git config --local user.name "GitHub Action"
git remote add origin https://github-action:$GITHUB_TOKEN@github.com/xmdhs/sing-geosite.git
git branch -M $1
git add .
git commit -m "Update $1"
git push -f origin $1
