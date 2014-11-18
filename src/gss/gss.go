package gss

/*
#cgo pkg-config: krb5-gssapi
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

static gss_OID_desc nth_oid_in_set(gss_OID_set_desc *oset, unsigned int n)
{
	return oset->elements[n];
}
static gss_buffer_desc nth_buffer_in_set(gss_buffer_set_desc *bset, unsigned int n)
{
	return bset->elements[n];
}
static gss_key_value_element_desc *alloc_n_kvset_elems(unsigned int n)
{
	return malloc(sizeof(gss_key_value_element_desc));
}
static void kv_set(gss_key_value_set_desc *kvset, int i, char *key, char *value)
{
	kvset->elements[i].key = key;
	kvset->elements[i].value = value;
}
static void free_kv_set(gss_key_value_set_desc kvset)
{
	unsigned i;
	for (i = 0; i < kvset.count; i++) {
		free((char *) kvset.elements[i].key);
		free((char *) kvset.elements[i].value);
	}
	free(kvset.elements);
}
static void free_gss_buffer(gss_buffer_desc buffer)
{
	free(buffer.value);
}
static void free_oid(gss_OID oid)
{
	if (oid != NULL) {
		free(oid->elements);
		free(oid);
	}
}
static void free_oid_set(gss_OID_set buffer)
{
	OM_uint32 minor;
	gss_release_oid_set(&minor, &buffer);
}
static void *
copyOid(unsigned char *bytes, int len)
{
	void *ret;

	if (len < 0) {
		return NULL;
	}
	ret = malloc(len);
	if (ret != NULL) {
		memcpy(ret, bytes, len);
	}
	return ret;
}
*/
import "C"
import "unsafe"
import "encoding/asn1"
import "fmt"

const (
	C_DCE_STYLE           = C.GSS_C_DCE_STYLE
	C_IDENTIFY_FLAG       = C.GSS_C_IDENTIFY_FLAG
	C_EXTENDED_ERROR_FLAG = C.GSS_C_EXTENDED_ERROR_FLAG

	//	C_NO_IOV_BUFFER = C.GSS_C_NO_IOV_BUFFER

	IOV_BUFFER_TYPE_EMPTY       = C.GSS_IOV_BUFFER_TYPE_EMPTY
	IOV_BUFFER_TYPE_DATA        = C.GSS_IOV_BUFFER_TYPE_DATA
	IOV_BUFFER_TYPE_HEADER      = C.GSS_IOV_BUFFER_TYPE_HEADER
	IOV_BUFFER_TYPE_MECH_PARAMS = C.GSS_IOV_BUFFER_TYPE_MECH_PARAMS
	IOV_BUFFER_TYPE_TRAILER     = C.GSS_IOV_BUFFER_TYPE_TRAILER
	IOV_BUFFER_TYPE_PADDING     = C.GSS_IOV_BUFFER_TYPE_PADDING
	IOV_BUFFER_TYPE_STREAM      = C.GSS_IOV_BUFFER_TYPE_STREAM
	IOV_BUFFER_TYPE_SIGN_ONLY   = C.GSS_IOV_BUFFER_TYPE_SIGN_ONLY
	IOV_BUFFER_TYPE_MIC_TOKEN   = C.GSS_IOV_BUFFER_TYPE_MIC_TOKEN
	IOV_BUFFER_FLAG_MASK        = C.GSS_IOV_BUFFER_FLAG_MASK
	IOV_BUFFER_FLAG_ALLOCATE    = C.GSS_IOV_BUFFER_FLAG_ALLOCATE
	IOV_BUFFER_FLAG_ALLOCATED   = C.GSS_IOV_BUFFER_FLAG_ALLOCATED

	//	C_NO_CRED_STORE

	C_BOTH     = C.GSS_C_BOTH
	C_INITIATE = C.GSS_C_INITIATE
	C_ACCEPT   = C.GSS_C_ACCEPT

	C_GSS_CODE  = C.GSS_C_GSS_CODE
	C_MECH_CODE = C.GSS_C_MECH_CODE

	C_AF_UNSPEC    = C.GSS_C_AF_UNSPEC
	C_AF_LOCAL     = C.GSS_C_AF_LOCAL
	C_AF_INET      = C.GSS_C_AF_INET
	C_AF_IMPLINK   = C.GSS_C_AF_IMPLINK
	C_AF_PUP       = C.GSS_C_AF_PUP
	C_AF_CHAOS     = C.GSS_C_AF_CHAOS
	C_AF_NS        = C.GSS_C_AF_NS
	C_AF_NBS       = C.GSS_C_AF_NBS
	C_AF_ECMA      = C.GSS_C_AF_ECMA
	C_AF_DATAKIT   = C.GSS_C_AF_DATAKIT
	C_AF_CCITT     = C.GSS_C_AF_CCITT
	C_AF_SNA       = C.GSS_C_AF_SNA
	C_AF_DECnet    = C.GSS_C_AF_DECnet
	C_AF_DLI       = C.GSS_C_AF_DLI
	C_AF_LAT       = C.GSS_C_AF_LAT
	C_AF_HYLINK    = C.GSS_C_AF_HYLINK
	C_AF_APPLETALK = C.GSS_C_AF_APPLETALK
	C_AF_BSC       = C.GSS_C_AF_BSC
	C_AF_DSS       = C.GSS_C_AF_DSS
	C_AF_OSI       = C.GSS_C_AF_OSI
	C_AF_NETBIOS   = C.GSS_C_AF_NETBIOS
	C_AF_X25       = C.GSS_C_AF_X25
	C_AF_NULLADDR  = C.GSS_C_AF_NULLADDR

	//	C_NO_NAME = nil
	//	C_NO_BUFFER = nil
	//	C_NO_OID = nil
	//	C_NO_OID_SET = nil
	//	C_NO_CONTEXT = nil
	//	C_NO_CREDENTIAL = nil
	//	C_NO_CHANNEL_BINDINGS = nil
	//	C_EMPTY_BUFFER = make([]byte, 0)

	//	C_NULL_OID = nil
	//	C_NULL_OID_SET = nil

	C_QOP_DEFAULT = C.GSS_C_QOP_DEFAULT
	C_INDEFINITE  = C.GSS_C_INDEFINITE

	S_COMPLETE                = C.GSS_S_COMPLETE
	C_CALLING_ERROR_OFFSET    = C.GSS_C_CALLING_ERROR_OFFSET
	C_ROUTINE_ERROR_OFFSET    = C.GSS_C_ROUTINE_ERROR_OFFSET
	C_SUPPLEMENTARY_OFFSET    = C.GSS_C_SUPPLEMENTARY_OFFSET
	C_CALLING_ERROR_MASK      = C.GSS_C_CALLING_ERROR_MASK
	C_ROUTINE_ERROR_MASK      = C.GSS_C_ROUTINE_ERROR_MASK
	C_SUPPLEMENTARY_MASK      = C.GSS_C_SUPPLEMENTARY_MASK
	S_CALL_INACCESSIBLE_READ  = C.GSS_S_CALL_INACCESSIBLE_READ
	S_CALL_INACCESSIBLE_WRITE = C.GSS_S_CALL_INACCESSIBLE_WRITE
	S_CALL_BAD_STRUCTURE      = C.GSS_S_CALL_BAD_STRUCTURE
	S_BAD_MECH                = C.GSS_S_BAD_MECH
	S_BAD_NAME                = C.GSS_S_BAD_NAME
	S_BAD_NAMETYPE            = C.GSS_S_BAD_NAMETYPE
	S_BAD_BINDINGS            = C.GSS_S_BAD_BINDINGS
	S_BAD_STATUS              = C.GSS_S_BAD_STATUS
	S_BAD_SIG                 = C.GSS_S_BAD_SIG
	S_NO_CRED                 = C.GSS_S_NO_CRED
	S_NO_CONTEXT              = C.GSS_S_NO_CONTEXT
	S_DEFECTIVE_TOKEN         = C.GSS_S_DEFECTIVE_TOKEN
	S_DEFECTIVE_CREDENTIAL    = C.GSS_S_DEFECTIVE_CREDENTIAL
	S_CREDENTIALS_EXPIRED     = C.GSS_S_CREDENTIALS_EXPIRED
	S_CONTEXT_EXPIRED         = C.GSS_S_CONTEXT_EXPIRED
	S_FAILURE                 = C.GSS_S_FAILURE
	S_BAD_QOP                 = C.GSS_S_BAD_QOP
	S_UNAUTHORIZED            = C.GSS_S_UNAUTHORIZED
	S_UNAVAILABLE             = C.GSS_S_UNAVAILABLE
	S_DUPLICATE_ELEMENT       = C.GSS_S_DUPLICATE_ELEMENT
	S_NAME_NOT_MN             = C.GSS_S_NAME_NOT_MN
	S_BAD_MECH_ATTR           = C.GSS_S_BAD_MECH_ATTR
	S_CONTINUE_NEEDED         = C.GSS_S_CONTINUE_NEEDED
	S_DUPLICATE_TOKEN         = C.GSS_S_DUPLICATE_TOKEN
	S_OLD_TOKEN               = C.GSS_S_OLD_TOKEN
	S_UNSEQ_TOKEN             = C.GSS_S_UNSEQ_TOKEN
	S_GAP_TOKEN               = C.GSS_S_GAP_TOKEN
	C_PRF_KEY_FULL            = C.GSS_C_PRF_KEY_FULL
	C_PRF_KEY_PARTIAL         = C.GSS_C_PRF_KEY_PARTIAL
	S_CRED_UNAVAIL            = C.GSS_S_CRED_UNAVAIL
)

var (
	KRB5_NT_HOSTBASED_SERVICE_NAME = coidToOid(*C.GSS_KRB5_NT_HOSTBASED_SERVICE_NAME)
	KRB5_NT_USER_NAME              = coidToOid(*C.GSS_KRB5_NT_USER_NAME)
	KRB5_NT_MACHINE_UID_NAME       = coidToOid(*C.GSS_KRB5_NT_MACHINE_UID_NAME)
	KRB5_NT_STRING_UID_NAME        = coidToOid(*C.GSS_KRB5_NT_STRING_UID_NAME)

	C_INQ_SSPI_SESSION_KEY  = coidToOid(*C.GSS_C_INQ_SSPI_SESSION_KEY)
	C_ATTR_LOCAL_LOGIN_USER = bufferToBytes(*C.GSS_C_ATTR_LOCAL_LOGIN_USER)
	C_NT_COMPOSITE_EXPORT   = coidToOid(*C.GSS_C_NT_COMPOSITE_EXPORT)

	C_NT_USER_NAME           = coidToOid(*C.GSS_C_NT_USER_NAME)
	C_NT_MACHINE_UID_NAME    = coidToOid(*C.GSS_C_NT_MACHINE_UID_NAME)
	C_NT_STRING_UID_NAME     = coidToOid(*C.GSS_C_NT_STRING_UID_NAME)
	C_NT_HOSTBASED_SERVICE_X = coidToOid(*C.GSS_C_NT_HOSTBASED_SERVICE_X)
	C_NT_HOSTBASED_SERVICE   = coidToOid(*C.GSS_C_NT_HOSTBASED_SERVICE)
	C_NT_ANONYMOUS           = coidToOid(*C.GSS_C_NT_ANONYMOUS)
	C_NT_EXPORT_NAME         = coidToOid(*C.GSS_C_NT_EXPORT_NAME)

	C_MA_MECH_CONCRETE  = coidToOid(*C.GSS_C_MA_MECH_CONCRETE)
	C_MA_MECH_PSEUDO    = coidToOid(*C.GSS_C_MA_MECH_PSEUDO)
	C_MA_MECH_COMPOSITE = coidToOid(*C.GSS_C_MA_MECH_COMPOSITE)
	C_MA_MECH_NEGO      = coidToOid(*C.GSS_C_MA_MECH_NEGO)
	C_MA_MECH_GLUE      = coidToOid(*C.GSS_C_MA_MECH_GLUE)
	C_MA_NOT_MECH       = coidToOid(*C.GSS_C_MA_NOT_MECH)
	C_MA_DEPRECATED     = coidToOid(*C.GSS_C_MA_DEPRECATED)
	C_MA_NOT_DFLT_MECH  = coidToOid(*C.GSS_C_MA_NOT_DFLT_MECH)
	C_MA_ITOK_FRAMED    = coidToOid(*C.GSS_C_MA_ITOK_FRAMED)
	C_MA_AUTH_INIT      = coidToOid(*C.GSS_C_MA_AUTH_INIT)
	C_MA_AUTH_TARG      = coidToOid(*C.GSS_C_MA_AUTH_TARG)
	C_MA_AUTH_INIT_INIT = coidToOid(*C.GSS_C_MA_AUTH_INIT_INIT)
	C_MA_AUTH_TARG_INIT = coidToOid(*C.GSS_C_MA_AUTH_TARG_INIT)
	C_MA_AUTH_INIT_ANON = coidToOid(*C.GSS_C_MA_AUTH_INIT_ANON)
	C_MA_AUTH_TARG_ANON = coidToOid(*C.GSS_C_MA_AUTH_TARG_ANON)
	C_MA_DELEG_CRED     = coidToOid(*C.GSS_C_MA_DELEG_CRED)
	C_MA_INTEG_PROT     = coidToOid(*C.GSS_C_MA_INTEG_PROT)
	C_MA_CONF_PROT      = coidToOid(*C.GSS_C_MA_CONF_PROT)
	C_MA_MIC            = coidToOid(*C.GSS_C_MA_MIC)
	C_MA_WRAP           = coidToOid(*C.GSS_C_MA_WRAP)
	C_MA_PROT_READY     = coidToOid(*C.GSS_C_MA_PROT_READY)
	C_MA_REPLAY_DET     = coidToOid(*C.GSS_C_MA_REPLAY_DET)
	C_MA_OOS_DET        = coidToOid(*C.GSS_C_MA_OOS_DET)
	C_MA_CBINDINGS      = coidToOid(*C.GSS_C_MA_CBINDINGS)
	C_MA_PFS            = coidToOid(*C.GSS_C_MA_PFS)
	C_MA_COMPRESS       = coidToOid(*C.GSS_C_MA_COMPRESS)
	C_MA_CTX_TRANS      = coidToOid(*C.GSS_C_MA_CTX_TRANS)

	KRB5_NT_PRINCIPAL_NAME = coidToOid(*C.GSS_KRB5_NT_PRINCIPAL_NAME)

	Mech_krb5          = coidToOid(*C.gss_mech_krb5)
	Mech_krb5_old      = coidToOid(*C.gss_mech_krb5_old)
	Mech_krb5_wrong    = coidToOid(*C.gss_mech_krb5_wrong)
	Mech_iakerb        = coidToOid(*C.gss_mech_iakerb)
	Mech_set_krb5      = coidSetToOids(C.gss_mech_set_krb5)
	Mech_set_krb5_old  = coidSetToOids(C.gss_mech_set_krb5_old)
	Mech_set_krb5_both = coidSetToOids(C.gss_mech_set_krb5_both)

	NT_krb5_name      = coidToOid(*C.gss_nt_krb5_name)
	NT_krb5_principal = coidToOid(*C.gss_nt_krb5_principal)
	//Krb5_gss_oid_array = coidToOid(C.krb5_gss_oid_array)
)

type CredHandle C.gss_cred_id_t

type ContextHandle C.gss_ctx_id_t

type InternalName C.gss_name_t

type ChannelBindings struct {
	initiatorAddressType, acceptorAddressType          uint32
	initiatorAddress, acceptorAddress, applicationData []byte
}

type Flags struct {
	deleg, delegPolicy, mutual, replay, sequence, anon, conf, integ bool
}

type IOV struct {
	data []byte
}

/* bytesToBuffer populates a gss_buffer_t with a borrowed reference to the
 * contents of the slice. */
func bytesToBuffer(data []byte) (cdesc C.gss_buffer_desc) {
	value := unsafe.Pointer(&data[0])
	length := C.size_t(len(data))

	cdesc.value = value
	cdesc.length = length
	return
}

/* bufferToBytes creates a byte array using the contents of the passed-in
 * buffer. */
func bufferToBytes(cdesc C.gss_buffer_desc) (b []byte) {
	length := C.int(cdesc.length)

	b = C.GoBytes(cdesc.value, length)
	return
}

/* buffersToBytes creates a byte array using the contents of the passed-in
 * buffer. */
func buffersToBytes(cdesc C.gss_buffer_set_desc) (b [][]byte) {
	count := uint(cdesc.count)
	var i uint

	b = make([][]byte, count)
	for i = 0; i < count; i++ {
		b[i] = bufferToBytes(C.nth_buffer_in_set(&cdesc, C.uint(i)))
	}
	return
}

/* Encode a tag and a length as a DER definite length */
func makeTagAndLength(tag, length int) (l []byte) {
	var count, bits int

	if length <= 127 {
		l = make([]byte, 2)
		l[0] = byte(tag)
		l[1] = byte(length)
		return
	}
	count = 0
	bits = length
	for bits != 0 {
		count++
		bits = bits >> 8
	}
	if count > 126 {
		return nil
	}
	l = make([]byte, 2+count)
	count = 0
	bits = length
	l[0] = byte(tag)
	for bits != 0 {
		l[len(l)-1-count] = byte(bits & 0xff)
		count++
		bits = bits >> 8
	}
	l[1] = byte((count | 0x80) & 0x7f)
	return
}

/* Split up a DER item */
func splitTagAndLength(tlv []byte) (class int, constructed bool, tag, length int, value []byte) {
	tbytes := 1
	lbytes := 1

	class = int((tlv[0] & 0xc0) >> 6)
	constructed = (tlv[0] & 0x20) != 0
	tag = int(tlv[0] & 0x1f)
	if tag == 0x1f {
		tag = 0
		for tlv[tbytes]&0x80 != 0 {
			tag = (tag << 7) + int(tlv[tbytes]&0x7f)
			tbytes++
		}
		tag = (tag << 7) + int(tlv[tbytes]&0x7f)
		tbytes++
	}
	if tlv[tbytes]&0x80 == 0 {
		length = int(tlv[tbytes] & 0x7f)
	} else {
		lbytes = int(tlv[tbytes] & 0x7f)
		if lbytes == 0 {
			value = nil
			return
		}
		for count := 0; count < lbytes; count++ {
			length = (length << 8) + int(tlv[tbytes+count]&0xff)
		}
	}
	if len(tlv) != tbytes+lbytes+length {
		value = nil
		return
	}
	value = tlv[(tbytes + lbytes):]
	return
}

/* coidToOid produces an asn1.ObjectIdentifier from the library's preferred
 * bytes-and-length representation, which is just the DER encoding without a
 * tag and length. */
func coidToOid(coid C.gss_OID_desc) (oid asn1.ObjectIdentifier) {
	length := C.int(coid.length)
	b := C.GoBytes(coid.elements, length)

	b = append(makeTagAndLength(6, len(b)), b...)
	asn1.Unmarshal(b, &oid)
	return
}

/* oidToCOid converts an asn1.ObjectIdentifier into an array of encoded bytes
 * without the tag and length, which is how the C library expects them to be
 * structured. */
func oidToCOid(oid asn1.ObjectIdentifier) (coid C.gss_OID) {
	b, _ := asn1.Marshal(oid)
	if b == nil {
		return
	}
	_, _, _, _, v := splitTagAndLength(b)
	if v == nil {
		return
	}
	length := len(v)
	if length == 0 {
		return
	}
	coid = C.gss_OID(C.calloc(1, C.size_t(unsafe.Sizeof(*coid))))
	coid.length = C.OM_uint32(length)
	coid.elements = C.copyOid((*C.uchar)(&v[0]), C.int(length))
	if coid.elements == nil {
		C.free_oid(coid)
		coid = nil
	}
	return
}

/* oidsToCOidSet converts an array of asn1.ObjectIdentifier items into an array
 * of arrays of encoded bytes-and-lengths, which is how the C library expects
 * them to be structured. */
func oidsToCOidSet(oidSet []asn1.ObjectIdentifier) (coids C.gss_OID_set) {
	var major, minor C.OM_uint32
	if oidSet == nil {
		return
	}
	major = C.gss_create_empty_oid_set(&minor, &coids)
	if major != 0 {
		return
	}

	for _, o := range oidSet {
		oid := oidToCOid(o)
		if oid == nil {
			continue
		}
		major = C.gss_add_oid_set_member(&minor, oid, &coids)
		C.free_oid(oid)
		if major != 0 {
			major = C.gss_release_oid_set(&minor, &coids)
			coids = nil
			return
		}
	}
	return
}

/* coidSetToOids produces an array of asn1.ObjectIdentifier items from the
 * library's preferred array-of-bytes-and-lengths representation. */
func coidSetToOids(coids *C.gss_OID_set_desc) (oidSet []asn1.ObjectIdentifier) {
	if coids == nil {
		return nil
	}

	oidSet = make([]asn1.ObjectIdentifier, coids.count)
	if oidSet == nil {
		return
	}

	for o := 0; o < int(coids.count); o++ {
		coid := C.nth_oid_in_set(coids, C.uint(o))
		oidSet[o] = coidToOid(coid)
	}

	return
}

func bindingsToCBindings(bindings *ChannelBindings) (cbindings C.gss_channel_bindings_t) {
	if bindings == nil {
		return nil
	}
	cbindings.initiator_addrtype = C.OM_uint32(bindings.initiatorAddressType)
	cbindings.initiator_address = bytesToBuffer(bindings.initiatorAddress)
	cbindings.acceptor_addrtype = C.OM_uint32(bindings.acceptorAddressType)
	cbindings.acceptor_address = bytesToBuffer(bindings.acceptorAddress)
	cbindings.application_data = bytesToBuffer(bindings.applicationData)
	return
}

func cbindingsToBindings(cbindings C.gss_channel_bindings_t) (bindings *ChannelBindings) {
	if cbindings == nil {
		return nil
	}
	bindings.initiatorAddressType = uint32(cbindings.initiator_addrtype)
	bindings.initiatorAddress = bufferToBytes(cbindings.initiator_address)
	bindings.acceptorAddressType = uint32(cbindings.acceptor_addrtype)
	bindings.acceptorAddress = bufferToBytes(cbindings.acceptor_address)
	bindings.applicationData = bufferToBytes(cbindings.application_data)
	return
}

func credStoreToKVSet(credStore [][2]string) (kvset C.gss_key_value_set_desc) {
	kvset.elements = C.alloc_n_kvset_elems(C.uint(len(credStore)))
	if kvset.elements == nil {
		return
	}
	for i, kv := range credStore {
		C.kv_set(&kvset, C.int(i), C.CString(kv[0]), C.CString(kv[1]))
	}
	kvset.count = C.OM_uint32(len(credStore))
	return
}

func AcquireCred(desiredName InternalName, lifetimeReq uint32, desiredMechs []asn1.ObjectIdentifier, credUsage uint32) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, lifetimeRec uint32) {
	name := C.gss_name_t(desiredName)
	lifetime := C.OM_uint32(lifetimeReq)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var desired, actual C.gss_OID_set
	var handle C.gss_cred_id_t

	desired = oidsToCOidSet(desiredMechs)
	major = C.gss_acquire_cred(&minor, name, lifetime, desired, usage, &handle, &actual, &lifetime)
	C.free_oid_set(desired)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandle = CredHandle(handle)
	actualMechs = coidSetToOids(actual)
	C.free_oid_set(actual)
	lifetimeRec = uint32(lifetime)
	return
}

func ReleaseCred(credHandle CredHandle) (majorStatus, minorStatus uint32) {
	handle := C.gss_cred_id_t(credHandle)
	var major, minor C.OM_uint32

	major = C.gss_release_cred(&minor, &handle)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func InquireCred(credHandle CredHandle) (majorStatus, minorStatus uint32, credName InternalName, lifetimeRec, credUsage uint32, mechSet []asn1.ObjectIdentifier) {
	handle := C.gss_cred_id_t(credHandle)
	name := C.gss_name_t(nil)
	var major, minor, lifetime C.OM_uint32
	var usage C.gss_cred_usage_t
	var mechs C.gss_OID_set

	major = C.gss_inquire_cred(&minor, handle, &name, &lifetime, &usage, &mechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	credName = InternalName(name)
	lifetimeRec = uint32(lifetime)
	credUsage = uint32(usage)
	mechSet = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	return
}

func AddCred(credHandle CredHandle, desiredName InternalName, desiredMech asn1.ObjectIdentifier, initiatorTimeReq, acceptorTimeReq, credUsage uint32, outputCredHandle CredHandle) (majorStatus, minorStatus uint32, outputCredHandleRec CredHandle, actualMechs []asn1.ObjectIdentifier, initiatorTimeRec, acceptorTimeRec uint32) {
	handle := C.gss_cred_id_t(credHandle)
	name := C.gss_name_t(desiredName)
	mech := oidToCOid(desiredMech)
	itime := C.OM_uint32(initiatorTimeReq)
	atime := C.OM_uint32(acceptorTimeReq)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_add_cred(&minor, handle, name, mech, usage, itime, atime, &handle, &mechs, &itime, &atime)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandleRec = CredHandle(handle)
	actualMechs = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	initiatorTimeRec = uint32(itime)
	acceptorTimeRec = uint32(atime)
	return
}

func InquireCredByMech(credHandle CredHandle, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, credName InternalName, initiatorLifetimeRec, acceptorLifetimeRec, credUsage uint32) {
	handle := C.gss_cred_id_t(credHandle)
	mech := oidToCOid(mechType)
	var major, minor, ilife, alife C.OM_uint32
	var name C.gss_name_t
	var usage C.gss_cred_usage_t

	major = C.gss_inquire_cred_by_mech(&minor, handle, mech, &name, &ilife, &alife, &usage)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	credName = InternalName(name)
	initiatorLifetimeRec = uint32(ilife)
	acceptorLifetimeRec = uint32(alife)
	credUsage = uint32(usage)
	return
}

func InitSecContext(claimantCredHandle CredHandle, contextHandle *ContextHandle, targName InternalName, mechType asn1.ObjectIdentifier, reqFlags Flags, lifetimeReq uint32, chanBindings *ChannelBindings, inputToken []byte) (majorStatus, minorStatus uint32, mechTypeRec asn1.ObjectIdentifier, outputToken []byte, recFlags Flags, transState, protReadyState bool, lifetimeRec uint32) {
	handle := C.gss_cred_id_t(claimantCredHandle)
	ctx := C.gss_ctx_id_t(*contextHandle)
	name := C.gss_name_t(targName)
	desired := oidToCOid(mechType)
	lifetime := C.OM_uint32(lifetimeReq)
	bindings := bindingsToCBindings(chanBindings)
	var major, minor, flags C.OM_uint32
	var itoken, otoken C.gss_buffer_desc
	var actual C.gss_OID

	if inputToken != nil {
		itoken = bytesToBuffer(inputToken)
	}
	if reqFlags.deleg {
		flags |= C.GSS_C_DELEG_FLAG
	}
	if reqFlags.delegPolicy {
		flags |= C.GSS_C_DELEG_POLICY_FLAG
	}
	if reqFlags.mutual {
		flags |= C.GSS_C_MUTUAL_FLAG
	}
	if reqFlags.replay {
		flags |= C.GSS_C_REPLAY_FLAG
	}
	if reqFlags.sequence {
		flags |= C.GSS_C_SEQUENCE_FLAG
	}
	if reqFlags.anon {
		flags |= C.GSS_C_ANON_FLAG
	}
	if reqFlags.conf {
		flags |= C.GSS_C_CONF_FLAG
	}
	if reqFlags.integ {
		flags |= C.GSS_C_INTEG_FLAG
	}

	major = C.gss_init_sec_context(&minor, handle, &ctx, name, desired, flags, lifetime, bindings, &itoken, &actual, &otoken, &flags, &lifetime)
	C.free_oid(desired)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	*contextHandle = ContextHandle(ctx)
	if actual != nil {
		mechTypeRec = coidToOid(*actual)
		major = C.gss_release_oid(&minor, &actual)
	}
	if otoken.length > 0 {
		outputToken = bufferToBytes(otoken)
		major = C.gss_release_buffer(&minor, &otoken)
	}
	if flags&C.GSS_C_DELEG_FLAG != 0 {
		recFlags.deleg = true
	}
	if flags&C.GSS_C_DELEG_POLICY_FLAG != 0 {
		recFlags.delegPolicy = true
	}
	if flags&C.GSS_C_MUTUAL_FLAG != 0 {
		recFlags.mutual = true
	}
	if flags&C.GSS_C_REPLAY_FLAG != 0 {
		recFlags.replay = true
	}
	if flags&C.GSS_C_SEQUENCE_FLAG != 0 {
		recFlags.sequence = true
	}
	if flags&C.GSS_C_ANON_FLAG != 0 {
		recFlags.anon = true
	}
	if flags&C.GSS_C_CONF_FLAG != 0 {
		recFlags.conf = true
	}
	if flags&C.GSS_C_INTEG_FLAG != 0 {
		recFlags.integ = true
	}
	if flags&C.GSS_C_TRANS_FLAG != 0 {
		transState = true
	}
	if flags&C.GSS_C_PROT_READY_FLAG != 0 {
		protReadyState = true
	}
	lifetimeRec = uint32(lifetime)
	return
}

func AcceptSecContext(acceptorCredHandle CredHandle, contextHandle *ContextHandle, chanBindings *ChannelBindings, inputToken []byte) (majorStatus, minorStatus uint32, srcName InternalName, mechType asn1.ObjectIdentifier, recFlags Flags, transState, protReadyState bool, lifetimeRec uint32, delegatedCredHandle CredHandle, outputToken []byte) {
	handle := C.gss_cred_id_t(acceptorCredHandle)
	ctx := C.gss_ctx_id_t(*contextHandle)
	bindings := bindingsToCBindings(chanBindings)
	var major, minor, flags, lifetime C.OM_uint32
	var name C.gss_name_t
	var itoken, otoken C.gss_buffer_desc
	var actual C.gss_OID
	var dhandle C.gss_cred_id_t

	if inputToken != nil {
		itoken = bytesToBuffer(inputToken)
	}

	major = C.gss_accept_sec_context(&minor, &ctx, handle, &itoken, bindings, &name, &actual, &otoken, &flags, &lifetime, &dhandle)
	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	srcName = InternalName(name)
	if actual != nil {
		mechType = coidToOid(*actual)
		major = C.gss_release_oid(&minor, &actual)
	}
	*contextHandle = ContextHandle(ctx)
	if flags&C.GSS_C_DELEG_FLAG != 0 {
		recFlags.deleg = true
	}
	if flags&C.GSS_C_MUTUAL_FLAG != 0 {
		recFlags.mutual = true
	}
	if flags&C.GSS_C_REPLAY_FLAG != 0 {
		recFlags.replay = true
	}
	if flags&C.GSS_C_SEQUENCE_FLAG != 0 {
		recFlags.sequence = true
	}
	if flags&C.GSS_C_ANON_FLAG != 0 {
		recFlags.anon = true
	}
	if flags&C.GSS_C_CONF_FLAG != 0 {
		recFlags.conf = true
	}
	if flags&C.GSS_C_INTEG_FLAG != 0 {
		recFlags.integ = true
	}
	if flags&C.GSS_C_TRANS_FLAG != 0 {
		transState = true
	}
	if flags&C.GSS_C_PROT_READY_FLAG != 0 {
		protReadyState = true
	}
	lifetimeRec = uint32(lifetime)
	delegatedCredHandle = CredHandle(dhandle)
	if otoken.length > 0 {
		outputToken = bufferToBytes(otoken)
		major = C.gss_release_buffer(&minor, &otoken)
	}
	return
}

func DeleteSecContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, outputContextToken []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	var major, minor C.OM_uint32
	var token C.gss_buffer_desc

	major = C.gss_delete_sec_context(&minor, &handle, &token)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if token.value != nil {
		outputContextToken = bufferToBytes(token)
		major = C.gss_release_buffer(&minor, &token)
	}
	return
}

func ProcessContextToken(contextHandle ContextHandle, contextToken []byte) (majorStatus, minorStatus uint32) {
	handle := C.gss_ctx_id_t(contextHandle)
	var major, minor C.OM_uint32
	var token C.gss_buffer_desc

	if contextToken != nil {
		token = bytesToBuffer(contextToken)
	}

	major = C.gss_process_context_token(&minor, handle, &token)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func ContextTime(contextHandle ContextHandle) (majorStatus, minorStatus, lifetimeRec uint32) {
	handle := C.gss_ctx_id_t(contextHandle)
	var major, minor, lifetime C.OM_uint32

	major = C.gss_context_time(&minor, handle, &lifetime)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	lifetimeRec = uint32(lifetime)
	return
}

func InquireContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, srcName, targName InternalName, lifetimeRec uint32, mechType asn1.ObjectIdentifier, delegState, mutualState, replayDetState, sequenceState, anonState, transState, protReadyState, confAvail, integAvail, locallyInitiated, open bool) {
	handle := C.gss_ctx_id_t(contextHandle)
	var major, minor, lifetime, flags C.OM_uint32
	var sname, tname C.gss_name_t
	var mech C.gss_OID
	var localinit, opened C.int

	major = C.gss_inquire_context(&minor, handle, &sname, &tname, &lifetime, &mech, &flags, &localinit, &opened)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	srcName = InternalName(sname)
	targName = InternalName(tname)
	lifetimeRec = uint32(lifetime)
	if mech != nil {
		mechType = coidToOid(*mech)
		major = C.gss_release_oid(&minor, &mech)
	}
	locallyInitiated = (localinit != 0)
	open = (opened != 0)
	return
}

func WrapSizeLimit(contextHandle ContextHandle, confReqFlag bool, qopReq uint32, outputSize uint32) (majorStatus, minorStatus, maxInputSize uint32) {
	handle := C.gss_ctx_id_t(contextHandle)
	qop := C.gss_qop_t(qopReq)
	output := C.OM_uint32(outputSize)
	var conf C.int
	var major, minor, input C.OM_uint32

	if confReqFlag {
		conf = 1
	} else {
		conf = 0
	}

	major = C.gss_wrap_size_limit(&minor, handle, conf, qop, output, &input)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	maxInputSize = uint32(input)
	return
}

func ExportSecContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, interProcessToken []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	var token C.gss_buffer_desc
	var major, minor C.OM_uint32

	major = C.gss_export_sec_context(&minor, &handle, &token)
	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if token.length > 0 {
		interProcessToken = bufferToBytes(token)
		major = C.gss_release_buffer(&minor, &token)
	}
	return
}

func ImportSecContext(interprocessToken []byte) (majorStatus, minorStatus uint32, contextHandle ContextHandle) {
	token := bytesToBuffer(interprocessToken)
	var major, minor C.OM_uint32
	var handle C.gss_ctx_id_t

	major = C.gss_import_sec_context(&minor, &token, &handle)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	contextHandle = ContextHandle(handle)
	return
}

func GetMIC(contextHandle ContextHandle, qopReq uint32, message []byte) (majorStatus, minorStatus uint32, perMessageToken []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	qop := C.gss_qop_t(qopReq)
	var msg, mic C.gss_buffer_desc
	var major, minor C.OM_uint32

	msg = bytesToBuffer(message)

	major = C.gss_get_mic(&minor, handle, qop, &msg, &mic)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if mic.length > 0 {
		perMessageToken = bufferToBytes(mic)
		major = C.gss_release_buffer(&minor, &mic)
	}
	return
}

func VerifyMIC(contextHandle ContextHandle, message, perMessageToken []byte) (majorStatus, minorStatus, qopState uint32) {
	handle := C.gss_ctx_id_t(contextHandle)
	msg := bytesToBuffer(message)
	mic := bytesToBuffer(perMessageToken)
	var major, minor C.OM_uint32
	var qop C.gss_qop_t

	major = C.gss_verify_mic(&minor, handle, &msg, &mic, &qop)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	qopState = uint32(qop)
	return
}

func Wrap(contextHandle ContextHandle, confReq bool, qopReq uint32, inputMessage []byte) (majorStatus, minorStatus uint32, confState bool, outputMessage []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	qop := C.gss_qop_t(qopReq)
	var major, minor C.OM_uint32
	var msg, wrapped C.gss_buffer_desc
	var conf C.int

	msg = bytesToBuffer(inputMessage)

	major = C.gss_wrap(&minor, handle, conf, qop, &msg, &conf, &wrapped)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	confState = (conf != 0)
	if wrapped.length > 0 {
		outputMessage = bufferToBytes(wrapped)
		major = C.gss_release_buffer(&minor, &wrapped)
	}
	return
}

func Unwrap(contextHandle ContextHandle, inputMessage []byte) (majorStatus, minorStatus uint32, confState bool, qopState uint32, outputMessage []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	wrapped := bytesToBuffer(inputMessage)
	var major, minor C.OM_uint32
	var msg C.gss_buffer_desc
	var conf C.int
	var qop C.gss_qop_t

	major = C.gss_unwrap(&minor, handle, &wrapped, &msg, &conf, &qop)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	confState = (conf != 0)
	qopState = uint32(qop)
	if msg.length > 0 {
		outputMessage = bufferToBytes(msg)
		major = C.gss_release_buffer(&minor, &msg)
	}
	return
}

func DisplayStatus(statusValue uint32, statusType int, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus, messageContext uint32, statusString string) {
	value := C.OM_uint32(statusValue)
	stype := C.int(statusType)
	mech := oidToCOid(mechType)
	var major, minor, mctx C.OM_uint32
	var status C.gss_buffer_desc

	major = C.gss_display_status(&minor, value, stype, mech, &mctx, &status)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	messageContext = uint32(mctx)
	if status.length > 0 {
		statusString = C.GoStringN((*C.char)(status.value), C.int(status.length))
		major = C.gss_release_buffer(&minor, &status)
	}
	return
}

func IndicateMechs() (majorStatus, minorStatus uint32, mechSet []asn1.ObjectIdentifier) {
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_indicate_mechs(&minor, &mechs)
	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	mechSet = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	return
}

func CompareName(name1, name2 InternalName) (majorStatus, minorStatus uint32, nameEqual bool) {
	n1 := C.gss_name_t(name1)
	n2 := C.gss_name_t(name2)
	var major, minor C.OM_uint32
	var equal C.int

	major = C.gss_compare_name(&minor, n1, n2, &equal)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	nameEqual = (equal != 0)
	return
}

func DisplayName(name InternalName) (majorStatus, minorStatus uint32, nameString string, nameType asn1.ObjectIdentifier) {
	n := C.gss_name_t(name)
	var major, minor C.OM_uint32
	var dname C.gss_buffer_desc
	var ntype C.gss_OID

	major = C.gss_display_name(&minor, n, &dname, &ntype)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if dname.length > 0 {
		nameString = C.GoStringN((*C.char)(dname.value), C.int(dname.length))
		major = C.gss_release_buffer(&minor, &dname)
	}
	if ntype != nil {
		nameType = coidToOid(*ntype)
		major = C.gss_release_oid(&minor, &ntype)
	}
	return
}

func ImportName(inputName string, nameType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, outputName InternalName) {
	ntype := oidToCOid(nameType)
	var major, minor C.OM_uint32
	var name C.gss_buffer_desc
	var iname C.gss_name_t

	name.length = C.size_t(len(inputName))
	name.value = unsafe.Pointer(C.CString(inputName))

	major = C.gss_import_name(&minor, &name, ntype, &iname)
	C.free_gss_buffer(name)
	C.free_oid(ntype)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputName = InternalName(iname)
	return
}

func ReleaseName(inputName InternalName) (majorStatus, minorStatus uint32) {
	name := C.gss_name_t(inputName)
	var major, minor C.OM_uint32

	major = C.gss_release_name(&minor, &name)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

/* ReleaseBuffer ReleaseOidSet CreateEmptyOidSet AddOidSetMember TestOidSetMember */

func InquireNamesForMech(inputMechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, nameTypeSet []asn1.ObjectIdentifier) {
	mech := oidToCOid(inputMechType)
	var major, minor C.OM_uint32
	var ntypes C.gss_OID_set

	major = C.gss_inquire_names_for_mech(&minor, mech, &ntypes)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	nameTypeSet = coidSetToOids(ntypes)
	C.free_oid_set(ntypes)
	return
}

func InquireMechsForName(inputName InternalName) (majorStatus, minorStatus uint32, mechTypes []asn1.ObjectIdentifier) {
	name := C.gss_name_t(inputName)
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_inquire_mechs_for_name(&minor, name, &mechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	mechTypes = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	return
}

func CanonicalizeName(inputName InternalName, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, outputName InternalName) {
	name := C.gss_name_t(inputName)
	mech := oidToCOid(mechType)
	var major, minor C.OM_uint32
	var newname C.gss_name_t

	major = C.gss_canonicalize_name(&minor, name, mech, &newname)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputName = InternalName(newname)
	return
}

func ExportName(inputName InternalName) (majorStatus, minorStatus uint32, outputName string) {
	name := C.gss_name_t(inputName)
	var major, minor C.OM_uint32
	var newname C.gss_buffer_desc

	major = C.gss_export_name(&minor, name, &newname)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if newname.length > 0 {
		outputName = C.GoStringN((*C.char)(newname.value), C.int(newname.length))
	}
	return
}

func DuplicateName(inputName InternalName) (majorStatus, minorStatus uint32, destName InternalName) {
	name := C.gss_name_t(inputName)
	var major, minor C.OM_uint32
	var newname C.gss_name_t

	major = C.gss_duplicate_name(&minor, name, &newname)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	destName = InternalName(newname)
	return
}

func PseudoRandom(contextHandle ContextHandle, prfKey int, prfIn []byte, desiredOutputLen int) (majorStatus, minorStatus uint32, prfOut []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	pkey := C.int(prfKey)
	pin := bytesToBuffer(prfIn)
	desired := C.ssize_t(desiredOutputLen)
	var major, minor C.OM_uint32
	var pout C.gss_buffer_desc

	major = C.gss_pseudo_random(&minor, handle, pkey, &pin, desired, &pout)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if pout.length > 0 {
		prfOut = bufferToBytes(pout)
	}
	return
}

func StoreCred(credHandle CredHandle, credUsage uint32, desiredMech asn1.ObjectIdentifier, overwriteCred, defCred bool) (majorStatus, minorStatus uint32, elementsStored []asn1.ObjectIdentifier, credUsageStored uint32) {
	handle := C.gss_cred_id_t(credHandle)
	usage := C.gss_cred_usage_t(credUsage)
	mech := oidToCOid(desiredMech)
	var major, minor, overwrite, def C.OM_uint32
	var stored C.gss_OID_set

	if overwriteCred {
		overwrite = 1
	}
	if defCred {
		def = 1
	}

	major = C.gss_store_cred(&minor, handle, usage, mech, overwrite, def, &stored, &usage)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	elementsStored = coidSetToOids(stored)
	C.free_oid_set(stored)
	credUsageStored = uint32(usage)
	return
}

func SetNegMechs(credHandle CredHandle, mechSet []asn1.ObjectIdentifier) (majorStatus, minorStatus uint32) {
	handle := C.gss_cred_id_t(credHandle)
	mechs := oidsToCOidSet(mechSet)
	var major, minor C.OM_uint32

	major = C.gss_set_neg_mechs(&minor, handle, mechs)
	C.free_oid_set(mechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func IndicateMechsByAttrs(desiredMechAttrs, exceptMechAttrs, criticalMechAttrs []asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, mechs []asn1.ObjectIdentifier) {
	desired := oidsToCOidSet(desiredMechAttrs)
	except := oidsToCOidSet(exceptMechAttrs)
	critical := oidsToCOidSet(criticalMechAttrs)
	var major, minor C.OM_uint32
	var selected C.gss_OID_set

	major = C.gss_indicate_mechs_by_attrs(&minor, desired, except, critical, &selected)
	C.free_oid_set(desired)
	C.free_oid_set(except)
	C.free_oid_set(critical)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	mechs = coidSetToOids(selected)
	C.free_oid_set(selected)
	return
}

func Krb5ExtractAuthzDataFromSecContext(contextHandle ContextHandle, adType int) (majorStatus, minorStatus uint32, adData []byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	adtype := C.int(adType)
	var major, minor C.OM_uint32
	var addata C.gss_buffer_desc

	major = C.gsskrb5_extract_authz_data_from_sec_context(&minor, handle, adtype, &addata)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if addata.length > 0 {
		adData = bufferToBytes(addata)
	}
	return
}

func PNameToUid(name InternalName, nmech asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, uid string) {
	iname := C.gss_name_t(name)
	mech := oidToCOid(nmech)
	var major, minor C.OM_uint32
	var id C.uid_t

	major = C.gss_pname_to_uid(&minor, iname, mech, &id)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	uid = ""
	if majorStatus == 0 {
		uid = fmt.Sprintf("%u", uint32(id))
	}
	return
}

func Localname(name InternalName, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, localName []byte) {
	iname := C.gss_name_t(name)
	mech := oidToCOid(mechType)
	var major, minor C.OM_uint32
	var lname C.gss_buffer_desc

	major = C.gss_localname(&major, iname, mech, &lname)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if lname.length > 0 {
		localName = bufferToBytes(lname)
		major = C.gss_release_buffer(&minor, &lname)
	}
	return
}

func Userok(name InternalName, username string) (ok bool) {
	iname := C.gss_name_t(name)
	lname := C.CString(username)
	var result C.int

	result = C.gss_userok(iname, lname)
	C.free(unsafe.Pointer(lname))

	ok = (result == 1)
	return
}

func AuthorizeLocalname(name, user InternalName) (majorStatus, minorStatus uint32) {
	iname := C.gss_name_t(name)
	uname := C.gss_name_t(user)
	var major, minor C.OM_uint32

	major = C.gss_authorize_localname(&minor, iname, uname)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func AcquireCredWithPassword(desiredName InternalName, password []byte, timeReq uint32, desiredMechs []asn1.ObjectIdentifier, credUsage uint32) (majorStatus, minorStatus uint32, cred CredHandle, actualMechs []asn1.ObjectIdentifier, timeRec uint32) {
	name := C.gss_name_t(desiredName)
	pwd := bytesToBuffer(password)
	time := C.OM_uint32(timeReq)
	dmechs := oidsToCOidSet(desiredMechs)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var amechs C.gss_OID_set
	var handle C.gss_cred_id_t

	major = C.gss_acquire_cred_with_password(&minor, name, &pwd, time, dmechs, usage, &handle, &amechs, &time)
	C.free_oid_set(dmechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	cred = CredHandle(handle)
	actualMechs = coidSetToOids(amechs)
	C.free_oid_set(amechs)
	timeRec = uint32(time)
	return
}

/*
func AddCredWithPassword(icred CredHandle, desiredName InternalName, desiredMech asn1.ObjectIdentifier, password []byte, credUsage uint32, initiatorTimeReq, acceptorTimeReq uint32) (majorStatus, minorStatus uint32, ocred CredHandle, actualMechs []asn1.ObjectIdentifier, initiatorTimeRec, acceptorTimeRec uint32) {
	cred := C.gss_cred_id_t(icred)
	name := C.gss_name_t(desiredName)
	dmech := oidToCOid(desiredMech)
	pwd := bytesToBuffer(password)
	usage := C.gss_cred_usage_t(credUsage)
	itime := C.OM_uint32(initiatorTimeReq)
	atime := C.OM_uint32(AcceptorTimeReq)
	var major, minor C.OM_uint32
	var amechs C.gss_OID_set

	major = C.gss_add_cred_with_password(&minor, cred, name, dmech, &pwd, usage, itime, atime, &cred, &amechs, &itime, &atime)
	C.free_oid(dmech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	ocred = CredHandle(cred)
	actualMechs = coidSetToOids(amechs)
	C.free_oid_set(amechs)
	initiatorTimeRec = uint32(itime)
	acceptorTimeRec = uint32(atime)
	return
}
*/

func InquireSecContextByOid(contextHandle ContextHandle, desiredObject asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, dataSet [][]byte) {
	handle := C.gss_ctx_id_t(contextHandle)
	obj := oidToCOid(desiredObject)
	var major, minor C.OM_uint32
	var data C.gss_buffer_set_t

	major = C.gss_inquire_sec_context_by_oid(&minor, handle, obj, &data)
	C.free_oid(obj)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if data != nil {
		dataSet = buffersToBytes(*data)
		major = C.gss_release_buffer_set(&minor, &data)
	}
	return
}

func InquireCredByOid(credHandle CredHandle, desiredObject asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, dataSet [][]byte) {
	handle := C.gss_cred_id_t(credHandle)
	obj := oidToCOid(desiredObject)
	var major, minor C.OM_uint32
	var data C.gss_buffer_set_t

	major = C.gss_inquire_cred_by_oid(&minor, handle, obj, &data)
	C.free_oid(obj)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if data != nil {
		dataSet = buffersToBytes(*data)
		major = C.gss_release_buffer_set(&minor, &data)
	}
	return
}

func SetSecContextOption(contextHandle *ContextHandle, desiredObject asn1.ObjectIdentifier, value []byte) (majorStatus, minorStatus uint32) {
	handle := C.gss_ctx_id_t(*contextHandle)
	obj := oidToCOid(desiredObject)
	val := bytesToBuffer(value)
	var major, minor C.OM_uint32

	major = C.gss_set_sec_context_option(&minor, &handle, obj, &val)
	C.free_oid(obj)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	*contextHandle = ContextHandle(handle)
	return
}

func SetCredOption(credHandle *CredHandle, desiredObject asn1.ObjectIdentifier, value []byte) (majorStatus, minorStatus uint32) {
	handle := C.gss_cred_id_t(*credHandle)
	obj := oidToCOid(desiredObject)
	val := bytesToBuffer(value)
	var major, minor C.OM_uint32

	major = C.gss_set_cred_option(&minor, &handle, obj, &val)
	C.free_oid(obj)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	*credHandle = CredHandle(handle)
	return
}

func MechInvoke(desiredMech, desiredObject asn1.ObjectIdentifier, value *[]byte) (majorStatus, minorStatus uint32) {
	mech := oidToCOid(desiredMech)
	obj := oidToCOid(desiredObject)
	val := bytesToBuffer(*value)
	var major, minor C.OM_uint32

	major = C.gssspi_mech_invoke(&minor, mech, obj, &val)
	C.free_oid(mech)
	C.free_oid(obj)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	*value = bufferToBytes(val)
	return
}

func WrapAEAD(contextHandle ContextHandle, confReq bool, qopReq uint32, inputAssociated, inputPayload []byte) (majorStatus, minorStatus uint32, confState bool, outputMessage []byte)
func UnwrapAEAD(contextHandle ContextHandle, inputMessage, inputAssociated []byte) (majorStatus, minorStatus uint32, outputPayload []byte, confState bool, qopState uint32)

func CompleteAuthToken(contextHandle ContextHandle, inputMessage []byte) (majorStatus, minorStatus uint32) {
	handle := C.gss_ctx_id_t(contextHandle)
	msg := bytesToBuffer(inputMessage)
	var major, minor C.OM_uint32

	major = C.gss_complete_auth_token(&minor, handle, &msg)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func WrapIOV(contextHandle ContextHandle, confReq bool, qopReq uint32, messages []IOV) (majorStatus, minorStatus uint32, confState bool)
func UnwrapIOV(contextHandle ContextHandle, messages []IOV) (majorStatus, minorStatus uint32, confState bool, qopState uint32)
func WrapIOVLength(contextHandle ContextHandle, confReq bool, qopReq uint32, messages []IOV) (majorStatus, minorStatus uint32, confState bool)
func GetMICIOV(contextHandle ContextHandle, qopReq uint32, messages []IOV) (majorStatus, minorStatus uint32)
func VerifyMICIOV(contextHandle ContextHandle, messages []IOV) (majorStatus, minorStatus uint32, qopState uint32)

func AcquireCredImpersonateName(impersonatorCredHandle CredHandle, desiredName InternalName, timeReq uint32, desiredMechs []asn1.ObjectIdentifier, credUsage uint32) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, timeRec uint32) {
	cred := C.gss_cred_id_t(impersonatorCredHandle)
	name := C.gss_name_t(desiredName)
	time := C.OM_uint32(timeReq)
	dmechs := oidsToCOidSet(desiredMechs)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var amechs C.gss_OID_set

	major = C.gss_acquire_cred_impersonate_name(&minor, cred, name, time, dmechs, usage, &cred, &amechs, &time)
	C.free_oid_set(dmechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandle = CredHandle(cred)
	actualMechs = coidSetToOids(amechs)
	C.free_oid_set(amechs)
	timeRec = uint32(time)
	return
}

func AddCredImpersonateName(inputCredHandle, impersonatorCredHandle CredHandle, desiredName InternalName, desiredMech asn1.ObjectIdentifier, credUsage, initiatorTimeReq, acceptorTimeReq uint32) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, initiatorTimeRec, acceptorTimeRec uint32) {
	cred := C.gss_cred_id_t(inputCredHandle)
	icred := C.gss_cred_id_t(impersonatorCredHandle)
	name := C.gss_name_t(desiredName)
	mech := oidToCOid(desiredMech)
	usage := C.gss_cred_usage_t(credUsage)
	itime := C.OM_uint32(initiatorTimeReq)
	atime := C.OM_uint32(acceptorTimeReq)
	var major, minor C.OM_uint32
	var ocred C.gss_cred_id_t
	var amechs C.gss_OID_set

	major = C.gss_add_cred_impersonate_name(&minor, cred, icred, name, mech, usage, itime, atime, &ocred, &amechs, &itime, &atime)
	C.free_oid(mech)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandle = CredHandle(ocred)
	actualMechs = coidSetToOids(amechs)
	C.free_oid_set(amechs)
	initiatorTimeRec = uint32(itime)
	acceptorTimeRec = uint32(atime)
	return
}

func DisplayNameExt(name InternalName, displayAsNameType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, displayName []byte) {
	iname := C.gss_name_t(name)
	ntype := oidToCOid(displayAsNameType)
	var major, minor C.OM_uint32
	var dname C.gss_buffer_desc

	major = C.gss_display_name_ext(&minor, iname, ntype, &dname)
	C.free_oid(ntype)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if dname.length > 0 {
		displayName = bufferToBytes(dname)
		major = C.gss_release_buffer(&minor, &dname)
	}
	return
}
func InquireName(name InternalName) (majorStatus, minorStatus uint32, nameIsMN bool, mnMech asn1.ObjectIdentifier, attrs [][]byte) {
	iname := C.gss_name_t(name)
	var major, minor C.OM_uint32
	var ismn C.int
	var oid C.gss_OID
	var buffers C.gss_buffer_set_t

	major = C.gss_inquire_name(&minor, iname, &ismn, &oid, &buffers)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	nameIsMN = (ismn != 0)
	if oid.length > 0 {
		mnMech = coidToOid(*oid)
		major = C.gss_release_oid(&minor, &oid)
	}
	if buffers != nil {
		attrs = buffersToBytes(*buffers)
		major = C.gss_release_buffer_set(&minor, &buffers)
	}
	return
}

func GetNameAttribute(name InternalName, attr []byte) (majorStatus, minorStatus uint32, authenticated, complete bool, value, displayValue []byte, more bool) {
	iname := C.gss_name_t(name)
	buffer := bytesToBuffer(attr)
	var major, minor C.OM_uint32
	var auth, comp, moar C.int
	var val, dval C.gss_buffer_desc

	major = C.gss_get_name_attribute(&minor, iname, &buffer, &auth, &comp, &val, &dval, &moar)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	authenticated = (auth != 0)
	complete = (comp != 0)
	if val.length > 0 {
		value = bufferToBytes(val)
		major = C.gss_release_buffer(&minor, &val)
	}
	if dval.length > 0 {
		displayValue = bufferToBytes(dval)
		major = C.gss_release_buffer(&minor, &dval)
	}
	more = (moar != 0)
	return
}

func SetNameAttribute(name InternalName, complete bool, attribute, value []byte) (majorStatus, minorStatus uint32) {
	iname := C.gss_name_t(name)
	var comp C.int
	attr := bytesToBuffer(attribute)
	val := bytesToBuffer(value)
	var major, minor C.OM_uint32

	if complete {
		comp = 1
	}
	major = C.gss_set_name_attribute(&minor, iname, comp, &attr, &val)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func DeleteNameAttribute(name InternalName, attribute []byte) (majorStatus, minorStatus uint32) {
	iname := C.gss_name_t(name)
	attr := bytesToBuffer(attribute)
	var major, minor C.OM_uint32

	major = C.gss_delete_name_attribute(&minor, iname, &attr)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	return
}

func ExportNameComposite(name InternalName) (majorStatus, minorStatus uint32, compositeName []byte) {
	iname := C.gss_name_t(name)
	var major, minor C.OM_uint32
	var cname C.gss_buffer_desc

	major = C.gss_export_name_composite(&minor, iname, &cname)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if cname.length > 0 {
		compositeName = bufferToBytes(cname)
		major = C.gss_release_buffer(&minor, &cname)
	}
	return
}

func AcquireCredFrom(desiredName InternalName, timeReq uint32, desiredMechs []asn1.ObjectIdentifier, desiredCredUsage uint32, credStore [][2]string) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, timeRec uint32) {
	name := C.gss_name_t(desiredName)
	time := C.OM_uint32(timeReq)
	dmechs := oidsToCOidSet(desiredMechs)
	usage := C.gss_cred_usage_t(desiredCredUsage)
	kvset := credStoreToKVSet(credStore)
	var major, minor C.OM_uint32
	var cred C.gss_cred_id_t
	var amechs C.gss_OID_set

	major = C.gss_acquire_cred_from(&minor, name, time, dmechs, usage, &kvset, &cred, &amechs, &time)
	C.free_oid_set(dmechs)
	C.free_kv_set(kvset)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandle = CredHandle(cred)
	actualMechs = coidSetToOids(amechs)
	C.free_oid_set(amechs)
	timeRec = uint32(time)
	return
}

func AddCredFrom(inputCredHandle CredHandle, desiredName InternalName, desiredMech asn1.ObjectIdentifier, desiredCredUsage, initiatorTimeReq, acceptorTimeReq uint32, credStore [][2]string) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, initiatorTimeRec, acceptorTimeRec uint32) {
	cred := C.gss_cred_id_t(inputCredHandle)
	name := C.gss_name_t(desiredName)
	mech := oidToCOid(desiredMech)
	usage := C.gss_cred_usage_t(desiredCredUsage)
	itime := C.OM_uint32(initiatorTimeReq)
	atime := C.OM_uint32(acceptorTimeReq)
	kvset := credStoreToKVSet(credStore)
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_add_cred_from(&minor, cred, name, mech, usage, itime, atime, &kvset, &cred, &mechs, &itime, &atime)
	C.free_oid(mech)
	C.free_kv_set(kvset)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	actualMechs = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	initiatorTimeRec = uint32(itime)
	acceptorTimeRec = uint32(atime)
	return
}

func StoreCredInto(inputCredHandle CredHandle, desiredCredUsage uint32, desiredMech asn1.ObjectIdentifier, overwriteCred, defaultCred bool, credStore [][2]string) (majorStatus, minorStatus uint32, elementsStored []asn1.ObjectIdentifier, credUsage uint32) {
	cred := C.gss_cred_id_t(inputCredHandle)
	usage := C.gss_cred_usage_t(credUsage)
	mech := oidToCOid(desiredMech)
	kvset := credStoreToKVSet(credStore)
	var major, minor, over, def C.OM_uint32
	var mechs C.gss_OID_set

	if overwriteCred {
		over = 1
	}
	if defaultCred {
		def = 1
	}

	major = C.gss_store_cred_into(&minor, cred, usage, mech, over, def, &kvset, &mechs, &usage)
	C.free_oid(mech)
	C.free_kv_set(kvset)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	elementsStored = coidSetToOids(mechs)
	C.free_oid_set(mechs)
	credUsage = uint32(usage)
	return
}

func ExportCred(credHandle CredHandle) (majorStatus, minorStatus uint32, token []byte) {
	handle := C.gss_cred_id_t(credHandle)
	var major, minor C.OM_uint32
	var buffer C.gss_buffer_desc

	major = C.gss_export_cred(&minor, handle, &buffer)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if buffer.length > 0 {
		token = bufferToBytes(buffer)
		major = C.gss_release_buffer(&minor, &buffer)
	}
	return
}

func ImportCred(token []byte) (majorStatus, minorStatus uint32, credHandle CredHandle) {
	buffer := bytesToBuffer(token)
	var major, minor C.OM_uint32
	var handle C.gss_cred_id_t

	major = C.gss_import_cred(&minor, &buffer, &handle)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	credHandle = CredHandle(handle)
	return
}
