package gss

/*
#cgo pkg-config: krb5-gssapi
#include <sys/types.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>

static gss_OID_desc nth_oid_in_set(gss_OID_set_desc *oset, unsigned int n)
{
	return oset->elements[n];
}
*/
import "C"
import "unsafe"
import "encoding/asn1"

type CredHandle C.gss_cred_id_t

type ContextHandle C.gss_ctx_id_t

type Oid asn1.ObjectIdentifier

type InternalName C.gss_name_t

type ChannelBindings C.gss_channel_bindings_t

func bytesToBuffer(data []byte) (cdesc C.gss_buffer_desc) {
	value := unsafe.Pointer(&data[0])
	length := C.size_t(len(data))

	cdesc.value = value
	cdesc.length = length
	return
}

func bufferToBytes(cdesc C.gss_buffer_desc) (b []byte) {
	length := C.int(cdesc.length)

	b = C.GoBytes(cdesc.value, length)
	return
}

func oidToCOid(oid Oid) (coid C.gss_OID_desc) {
	b, _ := asn1.Marshal(oid)
	if b == nil {
		return
	}
	elements := unsafe.Pointer(&b[0])
	length := C.OM_uint32(len(b))

	coid.elements = elements
	coid.length = length
	return
}

func coidToOid(coid C.gss_OID_desc) (oid Oid) {
	length := C.int(coid.length)
	b := C.GoBytes(coid.elements, length)

	asn1.Unmarshal(b, oid)
	return
}

func oidsToCOidSet(oidSet []Oid) (coids C.gss_OID_set) {
	var major, minor C.OM_uint32
	coids = nil
	if (oidSet == nil) {
		return
	}
	major = C.gss_create_empty_oid_set(&minor, &coids)
	if major != 0 {
		return
	}

	for o := 0; o < len(oidSet); o++ {
		oid := oidToCOid(oidSet[o])
		major = C.gss_add_oid_set_member(&minor, &oid, &coids)
		if major != 0 {
			major = C.gss_release_oid_set(&minor, &coids)
			coids = nil
			return
		}
	}
	return
}

func coidSetToOids(coids C.gss_OID_set_desc) (oidSet []Oid) {
	oidSet = make([]Oid, coids.count)
	if (oidSet == nil) {
		return
	}

	for o := 0; o < int(coids.count); o++ {
		var coid C.gss_OID_desc = C.nth_oid_in_set(&coids, C.uint(o))
		var oid Oid
		length := C.int(coid.length)
		b := C.GoBytes(coid.elements, length)
		asn1.Unmarshal(b, oid)
		oidSet[o] = oid
	}

	return
}

func AquireCred(desiredName InternalName, lifetimeReq uint32, desiredMechs []Oid, credUsage uint32) (majorStatus, minorStatus uint32, outputCredHandle CredHandle, actualMechs []Oid, lifetimeRec uint32) {
	var major, minor C.OM_uint32
	desired := C.gss_OID_set(nil)
	lifetime := C.OM_uint32(lifetimeReq)
	usage := C.gss_cred_usage_t(credUsage)
	name := C.gss_name_t(desiredName)
	actual := C.gss_OID_set(nil)
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
	} else {
		actualMechs = nil
	}
	lifetimeRec = uint32(lifetime)
	return
}

func ReleaseCred(credHandle CredHandle) (majorStatus, minorStatus uint32) {
	var major, minor C.OM_uint32
	handle := C.gss_cred_id_t(credHandle)

	major = C.gss_release_cred(&minor, &handle)

	minorStatus = uint32(minor)
	majorStatus = uint32(major)
	return
}

func InquireCred(credHandle CredHandle) (majorStatus, minorStatus uint32, credName InternalName, lifetimeRec, credUsage uint32, mechSet []Oid) {
	var major, minor, lifetime C.OM_uint32
	handle := C.gss_cred_id_t(credHandle)
	name := C.gss_name_t(nil)
	var usage C.gss_cred_usage_t
	mechs := C.gss_OID_set(nil)

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

func AddCred(credHandle CredHandle, desiredName string, initiatorTimeReq, acceptorTimeReq uint32, desiredMech Oid, credUsage, outputCredHandle CredHandle) (majorStatus, minorStatus uint32, outputCredHandleRec CredHandle, actualMechs []Oid, initiatorTimeRec, acceptorTimeRec, credUsageRec uint32, mechSet []Oid) {
	return
}

func InquireCredByMech(credHandle CredHandle, mechType Oid) (majorStatus, minorStatus uint32, credName InternalName, lifetimeRec, credUsage uint32) {
	return
}

func InitSecContext(claimantCredHandle CredHandle, inputContextHandle ContextHandle, targName InternalName, mechType Oid, delegReqFlag, mutualReqFlag, replayDetReqFlag, sequenceReqFlag, anonReqFlag, confReqFlag, integReqFlag bool, lifetimeReq uint32, chanBindings ChannelBindings, inputToken []byte) (majorStatus, minorStatus uint32, outputContextHandle ContextHandle, mechTypeRec Oid, outputToken []byte, delegState, mutualState, replayDetState, sequenceState, anonState, transState, protReadyState, confAvail, integAvail bool, lifetimeRec uint32) {
	return
}

func AcceptSecContext(acceptorCredHandle CredHandle, inputContextHandle ContextHandle, chanBindings ChannelBindings, inputToken []byte) (majorStatus, minorStatus uint32, srcName InternalName, mechType Oid, outputContextHandle ContextHandle, delegState, mutualState, replayDetState, sequenceState, anonState, transState, protReadyState, confAvail, integAvail bool, lifetimeRec uint32, delegatedCredHandle CredHandle, outputToken []byte) {
	return
}

func DeleteSecContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, outputContextToken []byte) {
	return
}

func ProcessContextToken(contextHandle ContextHandle, contextToken []byte) (majorStatus, minorStatus uint32) {
	return
}

func ContextTime(contextHandle ContextHandle) (majorStatus, minorStatus, lifetimeRec uint32) {
	return
}

func InquireContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, srcName, targName InternalName, lifetimeRec uint32, mechType Oid, delegState, mutualState, replayDetState, sequenceState, anonState, transState, protReadyState, confAvail, integAvail, locallyInitiated, open bool) {
	return
}

func WrapSizeLimit(contextHandle ContextHandle, confReqFlag bool, qop uint32, outputSize uint32) (majorStatus, minorStatus, maxInputSize uint32) {
	return
}

func ExportSecContext(contextHandle ContextHandle) (majorStatus, minorStatus uint32, interProcessToken []byte) {
	return
}

func ImportSecContext(interprocessToken []byte) (majorStatus, minorStatus uint32, contextHandle ContextHandle) {
	return
}

func GetMIC(contextHandle ContextHandle, qopReq uint32, message []byte) (majorStatus, minorStatus uint32, perMessageToken []byte) {
	return
}

func VerifyMIC(contextHandle ContextHandle, message, perMessageToken []byte) (qopState, majorStatus, minorStatus uint32) {
	return
}

func Wrap(contextHandle ContextHandle, confReq bool, qopReq uint32, inputMessage []byte) (majorStatus, minorStatus uint32, confState bool, outputMessage []byte) {
	return
}

func Unwrap(contextHandle ContextHandle, inputMessage []byte) (majorStatus, minorStatus uint32, confState bool, qopState uint32, outputMessage []byte) {
	return
}

func DisplayStatus(statusValue, statusType uint32, mechType Oid) (majorStatus, minorStatus uint32, statusString []string) {
	return
}

func IndicateMechs() (majorStatus, minorStatus uint32, mechSet []Oid) {
	return
}

func CompareName(name1, name2 InternalName) (majorStatus, minorStatus uint32, nameEqual bool) {
	return
}

func DisplayName(name InternalName) (majorStatus, minorStatus uint32, nameString string, nameType Oid) {
	return
}

func ImportName(inputName string, nameType Oid) (majorStatus, minorStatus uint32, outputName InternalName) {
	return
}

func ReleaseName(inputName InternalName) (majorStatus, minorStatus uint32) {
	return
}

/* ReleaseBuffer ReleaseOidSet CreateEmptyOidSet AddOidSetMember TestOidSetMember */

func InquireNamesForMech(inputMechType Oid) (majorStatus, minorStatus uint32, nameTypeSet []Oid) {
	return
}

func InquireMechsForName(inputName InternalName) (majorStatus, minorStatus uint32, mechTypes []Oid) {
	return
}

func CanonicalizeName(inputName InternalName, mechType Oid) (majorStatus, minorStatus uint32, outputName InternalName) {
	return
}

func ExportName(inputName InternalName) (majorStatus, minorStatus uint32, outputName InternalName) {
	return
}

func DuplicateName(inputName InternalName) (majorStatus, minorStatus uint32, destName InternalName) {
	return
}
