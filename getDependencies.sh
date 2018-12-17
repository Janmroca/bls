#!/bin/bash
set -euo pipefail

#---------------------------------------
# VARS
#---------------------------------------
dir="$(dirname $0)/../mcl"


#---------------------------------------
# MAIN
#---------------------------------------

if [ ! -d "$dir" ]; then
  # Download mcl
  git clone https://github.com/herumi/mcl.git "$dir"

  cd "$dir" > /dev/null 
  git checkout 5a16675 > /dev/null 2>&1
fi
