#!/bin/sh
# We only need the XDR parser for gss/proxy.
echo proxy-client
go build proxy-client.go proxy-misc.go
echo proxy-server
go build proxy-server.go proxy-misc.go
# We need development files for krb5 1.12 or newer for gss.
if pkg-config krb5-gssapi 2> /dev/null ; then
	echo gss-client
	go build gss-client.go gss-misc.go
	echo gss-server
	go build gss-server.go gss-misc.go
fi
