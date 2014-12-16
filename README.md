Package gss provides bindings for a C implementation of GSS-API (specifically, MIT Kerberos 1.12 or later) using cgo.  The provided API is relatively stable but still subject to change.

In broad strokes:
* gss\_buffer\_t is replaced by either []byte or string
* OIDs and OID sets are passed around as encoding/asn1 ObjectIdentifiers and arrays of encoding/asn1 ObjectIdentifiers
* memory management is still very much done manually

Package gss/proxy provides a client for [gss-proxy](https://fedorahosted.org/gss-proxy/).  The provided API is relatively stable but still subject to change, particularly around name attributes.
* OIDs and OID sets are passed around as encoding/asn1 ObjectIdentifiers and arrays of encoding/asn1 ObjectIdentifiers
* The single Release RPC is replaced with two wrappers: ReleaseCred and ReleaseSecCtx.
* The proxy doesn't currently allow use of SPNEGO "credentials", so a minimal SPNEGO implementation is added here.
