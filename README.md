Package gss provides bindings for a C implementation of GSS-API (specifically, MIT Kerberos 1.12 or later).  The provided API is not to be considered stable at this time.

In broad strokes:
* gss\_buffer\_t is replaced by either []byte or string
* OIDs and OID sets are passed around as encoding/asn1 ObjectIdentifiers and arrays of encoding/asn1 ObjectIdentifiers
