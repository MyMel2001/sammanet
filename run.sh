#!/bin/bash
cd "$(dirname "$0")"
git pull
npm i
node index.js >/dev/null 2>&1 &
