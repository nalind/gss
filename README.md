This package provides bindings for a C implementation of GSS-API.

In broad strokes:
* gss\_buffer\_t is replaced by []byte
* OIDs and OID sets are passed around as asn1.ObjectIdentifier and arrays of asn1.ObjectIdentifier
