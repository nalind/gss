set -x
go build proxy-client.go proxy-misc.go
go build proxy-server.go proxy-misc.go
go build gss-client.go   gss-misc.go
go build gss-server.go   gss-misc.go
