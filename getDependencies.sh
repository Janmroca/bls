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
fi
