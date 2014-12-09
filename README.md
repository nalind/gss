Package gss provides bindings for a C implementation of GSS-API (specifically, MIT Kerberos 1.12 or later) using cgo.  The provided API is not to be considered stable at this time.

In broad strokes:
* gss\_buffer\_t is replaced by either []byte or string
* OIDs and OID sets are passed around as encoding/asn1 ObjectIdentifiers and arrays of encoding/asn1 ObjectIdentifiers

Package gss/proxy provides a client for gss-proxy using github.com/davecgh/go-xdr/xdr2 to handle most of the RPC bits.  The provided API is also not considered stable yet.
* OIDs and OID sets are passed around as encoding/asn1 ObjectIdentifiers and arrays of encoding/asn1 ObjectIdentifiers
* The single Release RPC is replaced with two wrappers: ReleaseCred and ReleaseSecCtx.
