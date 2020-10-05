#!/bin/bash

set -euo pipefail

apt-get update &> /dev/null
apt-get install -qqy clang &> /dev/null
