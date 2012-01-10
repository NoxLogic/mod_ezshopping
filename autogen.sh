#!/bin/sh
set -e

aclocal
autoconf -f
automake-1.11 -a
./configure

