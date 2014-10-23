package gss

/*
#cgo pkg-config: krb5-gssapi
#include <sys/types.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>

static gss_OID_desc nth_oid_in_set(gss_OID_set_desc *oset, unsigned int n)
{
	return oset->elements[n];
}
*/
import "C"
import "unsafe"
import "encoding/asn1"
import "fmt"

type CredHandle C.gss_cred_id_t

type ContextHandle C.gss_ctx_id_t

type InternalName C.gss_name_t

type ChannelBindings struct {
	initiatorAddressType, acceptorAddressType uint32
	initiatorAddress, acceptorAddress, applicationData []byte
}

type Flags struct {
	deleg, delegPolicy, mutual, replay, sequence, anon, conf, integ bool
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
	l = make([]byte, 2 + count)
	count = 0
	bits = length
	l[0] = byte(tag)
	for bits != 0 {
		l[len(l) - 1 - count] = byte(bits & 0xff)
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
		for tlv[tbytes] & 0x80 != 0 {
			tag = (tag << 7) + int(tlv[tbytes] & 0x7f)
			tbytes++
		}
		tag = (tag << 7) + int(tlv[tbytes] & 0x7f)
		tbytes++
	}
	if tlv[tbytes] & 0x80 == 0 {
		length = int(tlv[tbytes] & 0x7f)
	} else {
		lbytes = int(tlv[tbytes] & 0x7f)
		if lbytes == 0 {
			value = nil
			return
		}
		for count := 0; count < lbytes; count++ {
			length = (length << 8) + int(tlv[tbytes + count] & 0xff)
		}
	}
	if len(tlv) != tbytes + lbytes + length {
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
func oidToCOid(oid asn1.ObjectIdentifier) (rawOid []byte, coid C.gss_OID_desc) {
	b, _ := asn1.Marshal(oid)
	if b == nil {
		return
	}
	_, _, _, _, v := splitTagAndLength(b)
	if v == nil {
		return
	}
	rawOid = v
	elements := unsafe.Pointer(&rawOid[0])
	length := C.OM_uint32(len(rawOid))

	coid.elements = elements
	coid.length = length
	return
}

/* oidsToCOidSet converts an array of asn1.ObjectIdentifier items into an array
 * of arrays of encoded bytes-and-lengths, which is how the C library expects
 * them to be structured. */
func oidsToCOidSet(oidSet []asn1.ObjectIdentifier) (coids C.gss_OID_set) {
	var major, minor C.OM_uint32
	if (oidSet == nil) {
		return
	}
	major = C.gss_create_empty_oid_set(&minor, &coids)
	if major != 0 {
		return
	}

	for _, o := range oidSet {
		_, oid := oidToCOid(o)
		major = C.gss_add_oid_set_member(&minor, &oid, &coids)
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
func coidSetToOids(coids C.gss_OID_set_desc) (oidSet []asn1.ObjectIdentifier) {
	oidSet = make([]asn1.ObjectIdentifier, coids.count)
	if (oidSet == nil) {
		return
	}

	for o := 0; o < int(coids.count); o++ {
		coid := C.nth_oid_in_set(&coids, C.uint(o))
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

func AcquireCred(desiredName InternalName, lifetimeReq uint32, desiredMechs []asn1.ObjectIdentifier, credUsage uint32) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []asn1.ObjectIdentifier, lifetimeRec uint32) {
	name := C.gss_name_t(desiredName)
	lifetime := C.OM_uint32(lifetimeReq)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var desired, actual C.gss_OID_set
	var handle C.gss_cred_id_t

	if desiredMechs != nil {
		desired = oidsToCOidSet(desiredMechs)
	}

	major = C.gss_acquire_cred(&minor, name, lifetime, desired, usage, &handle, &actual, &lifetime)

	if desired != nil {
		major = C.gss_release_oid_set(&minor, &desired)
	}
	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandle = CredHandle(handle)
	if actual != nil {
		actualMechs = coidSetToOids(*actual)
		major = C.gss_release_oid_set(&minor, &actual)
	}
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
	if (mechs != nil) {
		mechSet = coidSetToOids(*mechs)
		major = C.gss_release_oid_set(&minor, &mechs)
	}
	return
}

func AddCred(credHandle CredHandle, desiredName InternalName, desiredMech asn1.ObjectIdentifier, initiatorTimeReq, acceptorTimeReq, credUsage uint32, outputCredHandle CredHandle) (majorStatus, minorStatus uint32, outputCredHandleRec CredHandle, actualMechs []asn1.ObjectIdentifier, initiatorTimeRec, acceptorTimeRec uint32) {
	handle := C.gss_cred_id_t(credHandle)
	name := C.gss_name_t(desiredName)
	_, mech := oidToCOid(desiredMech)
	itime := C.OM_uint32(initiatorTimeReq)
	atime := C.OM_uint32(acceptorTimeReq)
	usage := C.gss_cred_usage_t(credUsage)
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_add_cred(&minor, handle, name, &mech, usage, itime, atime, &handle, &mechs, &itime, &atime)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	outputCredHandleRec = CredHandle(handle)
	if mechs != nil {
		actualMechs = coidSetToOids(*mechs)
		major = C.gss_release_oid_set(&minor, &mechs)
	}
	initiatorTimeRec = uint32(itime)
	acceptorTimeRec = uint32(atime)
	return
}

func InquireCredByMech(credHandle CredHandle, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, credName InternalName, initiatorLifetimeRec, acceptorLifetimeRec, credUsage uint32) {
	handle := C.gss_cred_id_t(credHandle)
	_, mech := oidToCOid(mechType)
	var major, minor, ilife, alife C.OM_uint32
	var name C.gss_name_t
	var usage C.gss_cred_usage_t

	major = C.gss_inquire_cred_by_mech(&minor, handle, &mech, &name, &ilife, &alife, &usage)

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
	_, desired := oidToCOid(mechType)
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
	major = C.gss_init_sec_context(&minor, handle, &ctx, name, &desired, flags, lifetime, bindings, &itoken, &actual, &otoken, &flags, &lifetime)

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
	if flags & C.GSS_C_DELEG_FLAG != 0 {
		recFlags.deleg = true
	}
	if flags & C.GSS_C_DELEG_POLICY_FLAG != 0 {
		recFlags.delegPolicy = true
	}
	if flags & C.GSS_C_MUTUAL_FLAG != 0 {
		recFlags.mutual = true
	}
	if flags & C.GSS_C_REPLAY_FLAG != 0 {
		recFlags.replay = true
	}
	if flags & C.GSS_C_SEQUENCE_FLAG != 0 {
		recFlags.sequence = true
	}
	if flags & C.GSS_C_ANON_FLAG != 0 {
		recFlags.anon = true
	}
	if flags & C.GSS_C_CONF_FLAG != 0 {
		recFlags.conf = true
	}
	if flags & C.GSS_C_INTEG_FLAG != 0 {
		recFlags.integ = true
	}
	if flags & C.GSS_C_TRANS_FLAG != 0 {
		transState = true
	}
	if flags & C.GSS_C_PROT_READY_FLAG != 0 {
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
	if flags & C.GSS_C_DELEG_FLAG != 0 {
		recFlags.deleg = true
	}
	if flags & C.GSS_C_MUTUAL_FLAG != 0 {
		recFlags.mutual = true
	}
	if flags & C.GSS_C_REPLAY_FLAG != 0 {
		recFlags.replay = true
	}
	if flags & C.GSS_C_SEQUENCE_FLAG != 0 {
		recFlags.sequence = true
	}
	if flags & C.GSS_C_ANON_FLAG != 0 {
		recFlags.anon = true
	}
	if flags & C.GSS_C_CONF_FLAG != 0 {
		recFlags.conf = true
	}
	if flags & C.GSS_C_INTEG_FLAG != 0 {
		recFlags.integ = true
	}
	if flags & C.GSS_C_TRANS_FLAG != 0 {
		transState = true
	}
	if flags & C.GSS_C_PROT_READY_FLAG != 0 {
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
	_, mech := oidToCOid(mechType)
	var major, minor, mctx C.OM_uint32
	var status C.gss_buffer_desc

	major = C.gss_display_status(&minor, value, stype, &mech, &mctx, &status)

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
	if mechs != nil {
		mechSet = coidSetToOids(*mechs)
		major = C.gss_release_oid_set(&minor, &mechs)
	}
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
	_, ntype := oidToCOid(nameType)
	var major, minor C.OM_uint32
	var name C.gss_buffer_desc
	var iname C.gss_name_t

	name.length = C.size_t(len(inputName))
	name.value = unsafe.Pointer(C.CString(inputName))

	major = C.gss_import_name(&minor, &name, &ntype, &iname)

	C.free(name.value)
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
	_, mech := oidToCOid(inputMechType)
	var major, minor C.OM_uint32
	var ntypes C.gss_OID_set

	major = C.gss_inquire_names_for_mech(&minor, &mech, &ntypes)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if ntypes != nil {
		nameTypeSet = coidSetToOids(*ntypes)
		major = C.gss_release_oid_set(&minor, &ntypes)
	}
	return
}

func InquireMechsForName(inputName InternalName) (majorStatus, minorStatus uint32, mechTypes []asn1.ObjectIdentifier) {
	name := C.gss_name_t(inputName)
	var major, minor C.OM_uint32
	var mechs C.gss_OID_set

	major = C.gss_inquire_mechs_for_name(&minor, name, &mechs)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if mechs != nil {
		mechTypes = coidSetToOids(*mechs)
		major = C.gss_release_oid_set(&minor, &mechs)
	}
	return
}

func CanonicalizeName(inputName InternalName, mechType asn1.ObjectIdentifier) (majorStatus, minorStatus uint32, outputName InternalName) {
	name := C.gss_name_t(inputName)
	_, mech := oidToCOid(mechType)
	var major, minor C.OM_uint32
	var newname C.gss_name_t

	major = C.gss_canonicalize_name(&minor, name, &mech, &newname)

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
	_, mech := oidToCOid(desiredMech)
	var major, minor, overwrite, def C.OM_uint32
	var stored C.gss_OID_set

	if overwriteCred {
		overwrite = 1
	}
	if defCred {
		def = 1
	}
	major = C.gss_store_cred(&minor, handle, usage, &mech, overwrite, def, &stored, &usage)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if stored != nil {
		elementsStored = coidSetToOids(*stored)
		major = C.gss_release_oid_set(&minor, &stored)
	}
	credUsageStored = uint32(usage)
	return
}

func SetNegMechs(credHandle CredHandle, mechSet []asn1.ObjectIdentifier) (majorStatus, minorStatus uint32) {
	handle := C.gss_cred_id_t(credHandle)
	mechs := oidsToCOidSet(mechSet)
	var major, minor C.OM_uint32

	major = C.gss_set_neg_mechs(&minor, handle, mechs)
	if mechs != nil {
		major = C.gss_release_oid_set(&minor, &mechs)
	}

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
	if desired != nil {
		major = C.gss_release_oid_set(&minor, &desired)
	}
	if except != nil {
		major = C.gss_release_oid_set(&minor, &except)
	}
	if critical != nil {
		major = C.gss_release_oid_set(&minor, &critical)
	}

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	if selected != nil {
		mechs = coidSetToOids(*selected)
		major = C.gss_release_oid_set(&minor, &selected)
	}
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
	_, mech := oidToCOid(nmech)
	var major, minor C.OM_uint32
	var id C.uid_t

	major = C.gss_pname_to_uid(&minor, iname, &mech, &id)

	majorStatus = uint32(major)
	minorStatus = uint32(minor)
	uid = ""
	if majorStatus == 0 {
		uid = fmt.Sprintf("%u", uint32(id))
	}
	return
}

func Localname()
func Userok()
func AuthorizeLocalname()
func AcquireCredWithPassword()
func AddCredWithPassword()
func InquireSecContextByOid()
func InquireCredByOid()
func SetSecContextOption()
func SetCredOption()
func MechInvoke()
func WrapAEAD()
func UnwrapAEAD()
func CompleteAuthToken()
func WrapIOV()
func UnwrapIOV()
func WrapIOVLength()
func GetMICIOV()
func VerifyMICIOV()
func AcquireCredImpersonateName()
func AddCredImpersonateName()
func DisplayNameExt()
func InquireName()
func GetNameAttribute()
func SetNameAttribute()
func DeleteNameAttribute()
func ExportNameAttribute()
func AcquireCredFrom()
func AddCredFrom()
func StoreCredInto()
func ExportCred()
func ImportCred()
