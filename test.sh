#!/bin/sh
# Run some tests on an EZShopping server.  This script assumes this structure:
#
# /shopdirroot/shop1/shop1file
# /shopdirroot/shop2/shop2file
# /shoplinkroot/shop3 -> /shopdirroot/shop1
# /wwwroot/wwwrootfile


host="localhost"
port="80"

echo "The following tests should succeed."

telnet $host $port <<EOF
GET /shop1/wwwrootfile HTTP/1.0

EOF
telnet $host $port <<EOF
GET /shop1/shop1file HTTP/1.0

EOF
telnet $host $port <<EOF
GET /shop2/shop2file HTTP/1.0

EOF
telnet $host $port <<EOF
GET /shop1file HTTP/1.0
ezshopping: shop3

EOF


echo "The following tests should fail."

telnet $host $port <<EOF
GET /shop1/nonexistent HTTP/1.0

EOF
telnet $host $port <<EOF
GET /shop1/shop2file HTTP/1.0

EOF

