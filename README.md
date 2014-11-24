This package provides bindings for a C implementation of GSS-API.  The provided API is *not* to be considered stable at this time.

In broad strokes:
* gss\_buffer\_t is replaced by either []byte or string
* OIDs and OID sets are passed around as asn1.ObjectIdentifier and arrays of asn1.ObjectIdentifier
* IOV and AEAD function and types are declared but functions are not currently defined
