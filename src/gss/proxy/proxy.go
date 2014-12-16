package proxy

import "bytes"
import "encoding/asn1"
import "fmt"
import "net"
import "strconv"
import "strings"
import "github.com/davecgh/go-xdr/xdr2"

const (
	/* The server we're using. */
	intGSSPROXY_PROG = 400112
	intGSSPROXY_VERS = 1

	/* Procedures. */
	intNULL                  = 0
	intINDICATE_MECHS        = 1
	intGET_CALL_CONTEXT      = 2
	intIMPORT_AND_CANON_NAME = 3
	intEXPORT_CRED           = 4
	intIMPORT_CRED           = 5
	intACQUIRE_CRED          = 6
	intSTORE_CRED            = 7
	intINIT_SEC_CONTEXT      = 8
	intACCEPT_SEC_CONTEXT    = 9
	intRELEASE_HANDLE        = 10
	intGET_MIC               = 11
	intVERIFY                = 12
	intWRAP                  = 13
	intUNWRAP                = 14
	intWRAP_SIZE_LIMIT       = 15

	/* Request the highest-available lifetime. */
	C_INDEFINITE = 0xffffffff

	/* Credential Usage values to be passed to ExportCred() and StoreCred(). */
	C_INITIATE = 1
	C_ACCEPT   = 2
	C_BOTH     = 3

	/* Ways to distinguish what's being released. */
	intGSSX_C_HANDLE_SEC_CTX = 0
	intGSSX_C_HANDLE_CRED    = 1

	/* Context flags. */
	intGSS_C_DELEG_FLAG        = 1
	intGSS_C_MUTUAL_FLAG       = 2
	intGSS_C_REPLAY_FLAG       = 4
	intGSS_C_SEQUENCE_FLAG     = 8
	intGSS_C_CONF_FLAG         = 16
	intGSS_C_INTEG_FLAG        = 32
	intGSS_C_ANON_FLAG         = 64
	intGSS_C_PROT_READY_FLAG   = 128
	intGSS_C_TRANS_FLAG        = 256
	intGSS_C_DELEG_POLICY_FLAG = 32768

	/* Status codes. */
	S_COMPLETE = 0

	intGSS_C_CALLING_ERROR_OFFSET = 24
	intGSS_C_ROUTINE_ERROR_OFFSET = 16
	intGSS_C_SUPPLEMENTARY_OFFSET = 0

	S_CONTINUE_NEEDED = (1 << (intGSS_C_SUPPLEMENTARY_OFFSET + 0))
	S_DUPLICATE_TOKEN = (1 << (intGSS_C_SUPPLEMENTARY_OFFSET + 1))
	S_OLD_TOKEN       = (1 << (intGSS_C_SUPPLEMENTARY_OFFSET + 2))
	S_UNSEQ_TOKEN     = (1 << (intGSS_C_SUPPLEMENTARY_OFFSET + 3))
	S_GAP_TOKEN       = (1 << (intGSS_C_SUPPLEMENTARY_OFFSET + 4))

	S_BAD_MECH             = (1 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_NAME             = (2 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_NAMETYPE         = (3 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_BINDINGS         = (4 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_STATUS           = (5 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_SIG              = (6 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_NO_CRED              = (7 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_NO_CONTEXT           = (8 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_DEFECTIVE_TOKEN      = (9 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_DEFECTIVE_CREDENTIAL = (10 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_CREDENTIALS_EXPIRED  = (11 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_CONTEXT_EXPIRED      = (12 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_FAILURE              = (13 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_QOP              = (14 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_UNAUTHORIZED         = (15 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_UNAVAILABLE          = (16 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_DUPLICATE_ELEMENT    = (17 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_NAME_NOT_MN          = (18 << intGSS_C_ROUTINE_ERROR_OFFSET)
	S_BAD_MECH_ATTR        = (19 << intGSS_C_ROUTINE_ERROR_OFFSET)

	/* Default quality of protection. */
	C_QOP_DEFAULT = 0

	/* SPNEGO status codes. */
	negStateAcceptCompleted  = 0
	negStateAcceptIncomplete = 1
	negStateReject           = 2
	negStateRequestMic       = 3
)

var (
	/* Known name types. */
	NT_USER_NAME           = parseOid("1.2.840.113554.1.2.1.1")
	NT_MACHINE_UID_NAME    = parseOid("1.2.840.113554.1.2.1.2")
	NT_STRING_UID_NAME     = parseOid("1.2.840.113554.1.2.1.3")
	NT_HOSTBASED_SERVICE   = parseOid("1.2.840.113554.1.2.1.4")
	NT_HOSTBASED_SERVICE_X = parseOid("1.3.6.1.5.6.2")
	NT_ANONYMOUS           = parseOid("1.3.6.1.5.6.3")
	NT_EXPORT_NAME         = parseOid("1.3.6.1.5.6.4")

	/* Known mechanisms. */
	MechKerberos5      = parseOid("1.2.840.113554.1.2.2")
	MechKerberos5Draft = parseOid("1.3.5.1.5.2")
	MechKerberos5Wrong = parseOid("1.2.840.48018.1.2.2")
	MechSPNEGO         = parseOid("1.3.6.1.5.5.2")
	MechIAKERB         = parseOid("1.3.6.1.5.2.5")

	/* The default mechanism list for SPNEGO. */
	defaultSPNEGOMechs = []asn1.ObjectIdentifier{MechKerberos5, MechKerberos5Draft, MechKerberos5Wrong}
)

type initialNegContextToken struct {
	ThisMech     asn1.ObjectIdentifier
	NegTokenInit negTokenInit `asn1:"explicit,tag:0"`
}
type negTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"optional,explicit,tag:1"`
	MechToken   []byte                  `asn1:"optional,explicit,tag:2"`
	MechListMic []byte                  `asn1:"optional,explicit,tag:3"`
}
type negTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"optional,explicit,tag:1"`
	ResponseToken []byte                `asn1:"optional,explicit,tag:2"`
	MechListMic   []byte                `asn1:"optional,explicit,tag:3"`
}
type negotiateInit struct {
	NegTokenInit negTokenInit `asn1:"explicit,tag:0"`
}
type negotiateResp struct {
	NegTokenResp negTokenResp `asn1:"explicit,tag:1"`
}

func parseOid(oids string) (oid asn1.ObjectIdentifier) {
	components := strings.Split(oids, ".")
	if len(components) > 0 {
		oid = make([]int, len(components))
		for i, component := range components {
			val, err := strconv.Atoi(component)
			if err != nil {
				fmt.Printf("Error parsing OID \"%s\".\n", oids)
				oid = nil
				return
			}
			oid[i] = val
		}
	}
	return
}

/* Flags describe requested parameters for a context passed to InitSecContext(), or the parameters of an established context as returned by AcceptSecContext(). */
type Flags struct {
	Deleg, DelegPolicy, Mutual, Replay, Sequence, Anon, Conf, Integ, Trans, ProtReady bool
}

func uncookFlags(flags Flags) (recFlags uint64) {
	if flags.Deleg {
		recFlags |= intGSS_C_DELEG_FLAG
	}
	if flags.DelegPolicy {
		recFlags |= intGSS_C_DELEG_POLICY_FLAG
	}
	if flags.Mutual {
		recFlags |= intGSS_C_MUTUAL_FLAG
	}
	if flags.Replay {
		recFlags |= intGSS_C_REPLAY_FLAG
	}
	if flags.Sequence {
		recFlags |= intGSS_C_SEQUENCE_FLAG
	}
	if flags.Anon {
		recFlags |= intGSS_C_ANON_FLAG
	}
	if flags.Conf {
		recFlags |= intGSS_C_CONF_FLAG
	}
	if flags.Integ {
		recFlags |= intGSS_C_INTEG_FLAG
	}
	if flags.Trans {
		recFlags |= intGSS_C_TRANS_FLAG
	}
	if flags.ProtReady {
		recFlags |= intGSS_C_PROT_READY_FLAG
	}
	return
}

func cookFlags(flags uint64) (recFlags Flags) {
	if flags&intGSS_C_DELEG_FLAG != 0 {
		recFlags.Deleg = true
	}
	if flags&intGSS_C_DELEG_POLICY_FLAG != 0 {
		recFlags.DelegPolicy = true
	}
	if flags&intGSS_C_MUTUAL_FLAG != 0 {
		recFlags.Mutual = true
	}
	if flags&intGSS_C_REPLAY_FLAG != 0 {
		recFlags.Replay = true
	}
	if flags&intGSS_C_SEQUENCE_FLAG != 0 {
		recFlags.Sequence = true
	}
	if flags&intGSS_C_ANON_FLAG != 0 {
		recFlags.Anon = true
	}
	if flags&intGSS_C_CONF_FLAG != 0 {
		recFlags.Conf = true
	}
	if flags&intGSS_C_INTEG_FLAG != 0 {
		recFlags.Integ = true
	}
	if flags&intGSS_C_TRANS_FLAG != 0 {
		recFlags.Trans = true
	}
	if flags&intGSS_C_PROT_READY_FLAG != 0 {
		recFlags.ProtReady = true
	}
	return
}

/* FlagsToRaw returns the integer representation of the flags structure, as would typically be used by C implementations.  It is here mainly to aid in running diagnostics. */
func FlagsToRaw(flags Flags) uint64 {
	return uncookFlags(flags)
}

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
	l[1] = byte(count | 0x80)
	return
}

func cookOid(oid []byte) (cooked asn1.ObjectIdentifier, err error) {
	_, err = asn1.Unmarshal(append(makeTagAndLength(6, len(oid)), oid...), &cooked)
	return
}

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
			length = (length << 8) + int(tlv[tbytes+1+count]&0xff)
		}
		lbytes++
	}
	if len(tlv) != tbytes+lbytes+length {
		value = nil
		return
	}
	value = tlv[(tbytes + lbytes):]
	return
}

func uncookOid(oid asn1.ObjectIdentifier) (raw []byte, err error) {
	b, err := asn1.Marshal(oid)
	if err != nil {
		return
	}
	_, _, _, _, raw = splitTagAndLength(b)
	return
}

type Option struct {
	Option, Value []byte
}

type rawMechAttr struct {
	Attr                      []byte
	Name, ShortDesc, LongDesc string
	Extensions                []Option
}

type MechAttr struct {
	Attr                      asn1.ObjectIdentifier
	Name, ShortDesc, LongDesc string
	Extensions                []Option
}

func uncookMechAttr(ma MechAttr) (raw rawMechAttr, err error) {
	raw.Attr, err = uncookOid(ma.Attr)
	if err != nil {
		return
	}
	raw.Name = ma.Name
	raw.ShortDesc = ma.ShortDesc
	raw.LongDesc = ma.LongDesc
	raw.Extensions = ma.Extensions
	return
}

func cookMechAttr(ma rawMechAttr) (cooked MechAttr, err error) {
	cooked.Attr, err = cookOid(ma.Attr)
	if err != nil {
		return
	}
	cooked.Name = ma.Name
	cooked.ShortDesc = ma.ShortDesc
	cooked.LongDesc = ma.LongDesc
	cooked.Extensions = ma.Extensions
	return
}

type rawMechInfo struct {
	Mech                                                             []byte
	NameTypes, MechAttrs, KnownMechAttrs, CredOptions, SecCtxOptions [][]byte
	SaslNameSaslMechName, SaslNameMechName, SaslNameMechDesc         string
	Extensions                                                       []Option
}

type MechInfo struct {
	Mech                                                             asn1.ObjectIdentifier
	NameTypes, MechAttrs, KnownMechAttrs, CredOptions, SecCtxOptions []asn1.ObjectIdentifier
	SaslNameSaslMechName, SaslNameMechName, SaslNameMechDesc         string
	Extensions                                                       []Option
}

func uncookMechInfo(mi MechInfo) (raw rawMechInfo, err error) {
	raw.Mech, err = uncookOid(mi.Mech)
	if err != nil {
		return
	}
	raw.NameTypes = make([][]byte, len(mi.NameTypes))
	for i, nt := range mi.NameTypes {
		raw.NameTypes[i], err = uncookOid(nt)
		if err != nil {
			return
		}
	}
	raw.MechAttrs = make([][]byte, len(mi.MechAttrs))
	for i, ma := range mi.MechAttrs {
		raw.MechAttrs[i], err = uncookOid(ma)
		if err != nil {
			return
		}
	}
	raw.KnownMechAttrs = make([][]byte, len(mi.KnownMechAttrs))
	for i, km := range mi.KnownMechAttrs {
		raw.KnownMechAttrs[i], err = uncookOid(km)
		if err != nil {
			return
		}
	}
	raw.CredOptions = make([][]byte, len(mi.CredOptions))
	for i, co := range mi.CredOptions {
		raw.CredOptions[i], err = uncookOid(co)
		if err != nil {
			return
		}
	}
	raw.SecCtxOptions = make([][]byte, len(mi.SecCtxOptions))
	for i, so := range mi.SecCtxOptions {
		raw.SecCtxOptions[i], err = uncookOid(so)
		if err != nil {
			return
		}
	}
	raw.SaslNameSaslMechName = mi.SaslNameSaslMechName
	raw.SaslNameMechName = mi.SaslNameMechName
	raw.SaslNameMechDesc = mi.SaslNameMechDesc
	raw.Extensions = mi.Extensions
	return
}

func cookMechInfo(mi rawMechInfo) (cooked MechInfo, err error) {
	cooked.Mech, err = cookOid(mi.Mech)
	if err != nil {
		return
	}
	cooked.NameTypes = make([]asn1.ObjectIdentifier, len(mi.NameTypes))
	for i, nt := range mi.NameTypes {
		cooked.NameTypes[i], err = cookOid(nt)
		if err != nil {
			return
		}
	}
	cooked.MechAttrs = make([]asn1.ObjectIdentifier, len(mi.MechAttrs))
	for i, ma := range mi.MechAttrs {
		cooked.MechAttrs[i], err = cookOid(ma)
		if err != nil {
			return
		}
	}
	cooked.KnownMechAttrs = make([]asn1.ObjectIdentifier, len(mi.KnownMechAttrs))
	for i, km := range mi.KnownMechAttrs {
		cooked.KnownMechAttrs[i], err = cookOid(km)
		if err != nil {
			return
		}
	}
	cooked.CredOptions = make([]asn1.ObjectIdentifier, len(mi.CredOptions))
	for i, co := range mi.CredOptions {
		cooked.CredOptions[i], err = cookOid(co)
		if err != nil {
			return
		}
	}
	cooked.SecCtxOptions = make([]asn1.ObjectIdentifier, len(mi.SecCtxOptions))
	for i, so := range mi.SecCtxOptions {
		cooked.SecCtxOptions[i], err = cookOid(so)
		if err != nil {
			return
		}
	}
	cooked.SaslNameSaslMechName = mi.SaslNameSaslMechName
	cooked.SaslNameMechName = mi.SaslNameMechName
	cooked.SaslNameMechDesc = mi.SaslNameMechDesc
	cooked.Extensions = mi.Extensions
	return
}

type rawNameAttr struct {
	Attr, Value []byte
	Extensions  []Option
}

type NameAttr struct {
	Attr       string
	Value      []byte
	Extensions []Option
}

func cookNameAttr(a rawNameAttr) (cooked NameAttr, err error) {
	buf := bytes.NewBuffer(a.Attr)
	cooked.Attr = buf.String()
	cooked.Value = a.Value
	cooked.Extensions = a.Extensions
	return
}

func uncookNameAttr(a NameAttr) (raw rawNameAttr, err error) {
	buf := bytes.NewBufferString(a.Attr)
	raw.Attr = buf.Bytes()
	raw.Value = a.Value
	raw.Extensions = a.Extensions
	return
}

type rawStatus struct {
	MajorStatus                          uint64
	Mech                                 []byte
	MinorStatus                          uint64
	MajorStatusString, MinorStatusString string
	ServerCtx                            []byte
	Options                              []Option
}

type Status struct {
	MajorStatus                          uint64
	Mech                                 asn1.ObjectIdentifier
	MinorStatus                          uint64
	MajorStatusString, MinorStatusString string
	ServerCtx                            []byte
	Options                              []Option
}

func cookStatus(s rawStatus) (cooked Status, err error) {
	cooked.MajorStatus = s.MajorStatus
	if len(s.Mech) > 0 {
		cooked.Mech, err = cookOid(s.Mech)
		if err != nil {
			return
		}
	}
	cooked.MinorStatus = s.MinorStatus
	cooked.MajorStatusString = s.MajorStatusString
	cooked.MinorStatusString = s.MinorStatusString
	cooked.Options = s.Options
	return
}

type CallCtx struct {
	Locale    string
	ServerCtx []byte
	Options   []Option
}

type rawName struct {
	DisplayName                                   string
	NameType, ExportedName, ExportedCompositeName []byte
	NameAttributes                                []rawNameAttr
	Extensions                                    []Option
}

type Name struct {
	DisplayName                         string
	NameType                            asn1.ObjectIdentifier
	ExportedName, ExportedCompositeName []byte
	NameAttributes                      []NameAttr
	Extensions                          []Option
}

func uncookName(n Name) (raw rawName, err error) {
	var natmp rawNameAttr
	raw.DisplayName = n.DisplayName
	if len(n.NameType) > 0 {
		raw.NameType, err = uncookOid(n.NameType)
		if err != nil {
			return
		}
	}
	raw.ExportedName = n.ExportedName
	raw.ExportedCompositeName = n.ExportedCompositeName
	raw.NameAttributes = make([]rawNameAttr, len(n.NameAttributes))
	for i, na := range n.NameAttributes {
		natmp, err = uncookNameAttr(na)
		if err != nil {
			return
		}
		raw.NameAttributes[i] = natmp
	}
	raw.Extensions = n.Extensions
	return
}

func cookName(n rawName) (cooked Name, err error) {
	var natmp NameAttr
	cooked.DisplayName = n.DisplayName
	if len(n.NameType) > 0 {
		cooked.NameType, err = cookOid(n.NameType)
		if err != nil {
			return
		}
	}
	cooked.ExportedName = n.ExportedName
	cooked.ExportedCompositeName = n.ExportedCompositeName
	cooked.NameAttributes = make([]NameAttr, len(n.NameAttributes))
	for i, na := range n.NameAttributes {
		natmp, err = cookNameAttr(na)
		if err != nil {
			return
		}
		cooked.NameAttributes[i] = natmp
	}
	cooked.Extensions = n.Extensions
	return
}

type rawCredElement struct {
	MN                                rawName
	Mech                              []byte
	CredUsage                         uint32
	InitiatorTimeRec, AcceptorTimeRec uint64
	Options                           []Option
}

type CredElement struct {
	MN                                Name
	Mech                              asn1.ObjectIdentifier
	CredUsage                         int
	InitiatorTimeRec, AcceptorTimeRec uint64
	Options                           []Option
}

func uncookCredElement(ce CredElement) (raw rawCredElement, err error) {
	raw.MN, err = uncookName(ce.MN)
	if err != nil {
		return
	}
	raw.Mech, err = uncookOid(ce.Mech)
	if err != nil {
		return
	}
	raw.CredUsage = uint32(ce.CredUsage)
	raw.InitiatorTimeRec = ce.InitiatorTimeRec
	raw.AcceptorTimeRec = ce.AcceptorTimeRec
	raw.Options = ce.Options
	return
}

func cookCredElement(c rawCredElement) (cooked CredElement, err error) {
	cooked.MN, err = cookName(c.MN)
	if err != nil {
		return
	}
	cooked.Mech, err = cookOid(c.Mech)
	if err != nil {
		return
	}
	cooked.CredUsage = int(c.CredUsage)
	cooked.InitiatorTimeRec = c.InitiatorTimeRec
	cooked.AcceptorTimeRec = c.AcceptorTimeRec
	cooked.Options = c.Options
	return
}

type rawCred struct {
	DesiredName         rawName
	Elements            []rawCredElement
	CredHandleReference []byte
	NeedsRelease        bool
}

type Cred struct {
	DesiredName         Name
	Elements            []CredElement
	CredHandleReference []byte
	NeedsRelease        bool
	negotiateMechs      *[]asn1.ObjectIdentifier
}

func uncookCred(c Cred) (raw rawCred, err error) {
	raw.DesiredName, err = uncookName(c.DesiredName)
	if err != nil {
		return
	}
	raw.Elements = make([]rawCredElement, len(c.Elements))
	for i, ce := range c.Elements {
		raw.Elements[i], err = uncookCredElement(ce)
		if err != nil {
			return
		}
	}
	raw.CredHandleReference = c.CredHandleReference
	raw.NeedsRelease = c.NeedsRelease
	return
}

func cookCred(c rawCred) (cooked Cred, err error) {
	cooked.DesiredName, err = cookName(c.DesiredName)
	if err != nil {
		return
	}
	cooked.Elements = make([]CredElement, len(c.Elements))
	for i, ce := range c.Elements {
		cooked.Elements[i], err = cookCredElement(ce)
		if err != nil {
			return
		}
	}
	cooked.CredHandleReference = c.CredHandleReference
	cooked.NeedsRelease = c.NeedsRelease
	return
}

type rawSecCtx struct {
	ExportedContextToken, State []byte
	NeedsRelease                bool
	Mech                        []byte
	SrcName, TargName           rawName
	Lifetime, CtxFlags          uint64
	LocallyInitiated, Open      bool
	Options                     []Option
}

type SecCtx struct {
	ExportedContextToken, State []byte
	NeedsRelease                bool
	Mech                        asn1.ObjectIdentifier
	SrcName, TargName           Name
	Lifetime                    uint64
	Flags                       Flags
	LocallyInitiated, Open      bool
	Options                     []Option
}

func uncookSecCtx(s SecCtx) (raw rawSecCtx, err error) {
	raw.ExportedContextToken = s.ExportedContextToken
	raw.State = s.State
	raw.NeedsRelease = s.NeedsRelease
	if len(s.Mech) > 0 {
		raw.Mech, err = uncookOid(s.Mech)
		if err != nil {
			return
		}
	}
	raw.SrcName, err = uncookName(s.SrcName)
	if err != nil {
		return
	}
	raw.TargName, err = uncookName(s.TargName)
	if err != nil {
		return
	}
	raw.Lifetime = s.Lifetime
	raw.CtxFlags = uncookFlags(s.Flags)
	raw.LocallyInitiated = s.LocallyInitiated
	raw.Open = s.Open
	raw.Options = s.Options
	return
}

func cookSecCtx(c rawSecCtx) (cooked SecCtx, err error) {
	cooked.ExportedContextToken = c.ExportedContextToken
	cooked.State = c.State
	cooked.NeedsRelease = c.NeedsRelease
	if len(c.Mech) > 0 {
		cooked.Mech, err = cookOid(c.Mech)
		if err != nil {
			return
		}
	}
	cooked.SrcName, err = cookName(c.SrcName)
	if err != nil {
		return
	}
	cooked.TargName, err = cookName(c.TargName)
	if err != nil {
		return
	}
	cooked.Lifetime = c.Lifetime
	cooked.Flags = cookFlags(c.CtxFlags)
	cooked.LocallyInitiated = c.LocallyInitiated
	cooked.Open = c.Open
	cooked.Options = c.Options
	return
}

type IndicateMechsResults struct {
	Status              Status
	Mechs               []MechInfo
	MechAttrDescs       []MechAttr
	SupportedExtensions [][]byte
	Extensions          []Option
}

/* IndicateMechs returns a list of the mechanisms supported by this proxy. */
func IndicateMechs(conn *net.Conn, callCtx *CallCtx) (results IndicateMechsResults, err error) {
	var args struct {
		CallCtx CallCtx
	}
	var res struct {
		Status              rawStatus
		Mechs               []rawMechInfo
		MechAttrDescs       []rawMechAttr
		SupportedExtensions [][]byte
		Extensions          []Option
	}
	var cooked IndicateMechsResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intINDICATE_MECHS, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	cooked.Mechs = make([]MechInfo, len(res.Mechs))
	for i, m := range res.Mechs {
		cooked.Mechs[i], err = cookMechInfo(m)
		if err != nil {
			return
		}
	}
	cooked.MechAttrDescs = make([]MechAttr, len(res.MechAttrDescs))
	for i, ma := range res.MechAttrDescs {
		cooked.MechAttrDescs[i], err = cookMechAttr(ma)
		if err != nil {
			return
		}
	}
	cooked.SupportedExtensions = res.SupportedExtensions
	cooked.Extensions = res.Extensions

	results = cooked
	return
}

type GetCallContextResults struct {
	Status    Status
	ServerCtx []byte
	Options   []Option
}

/* GetCallContext returns a ServerCtx value which should be used in subsequent calls to this proxy server.  As of gss-proxy 0.3.1, the proxy implementation is a no-op. */
func GetCallContext(conn *net.Conn, callCtx *CallCtx, options []Option) (results GetCallContextResults, err error) {
	var args struct {
		CallCtx CallCtx
		Options []Option
	}
	var res GetCallContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intGET_CALL_CONTEXT, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	callCtx.ServerCtx = res.ServerCtx

	results = res
	return
}

type ImportAndCanonNameResults struct {
	Status  Status
	Name    *Name
	Options []Option
}

/* ImportAndCanonName imports and canonicalizes a name.  An uncanonicalized name can be used after its DisplayName and NameType are initialized, so this function is not always used. */
func ImportAndCanonName(conn *net.Conn, callCtx *CallCtx, name Name, mech asn1.ObjectIdentifier, nameAttrs []NameAttr, options []Option) (results ImportAndCanonNameResults, err error) {
	var args struct {
		CallCtx   CallCtx
		InputName rawName
		Mech      []byte
		NameAttrs []rawNameAttr
		Options   []Option
	}
	var res struct {
		Status     rawStatus
		OutputName []rawName
		Options    []Option
	}
	var cooked ImportAndCanonNameResults
	var ntmp Name
	var natmp rawNameAttr
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.InputName, err = uncookName(name)
	if err != nil {
		return
	}
	args.Mech, err = uncookOid(mech)
	if err != nil {
		return
	}
	args.NameAttrs = make([]rawNameAttr, len(nameAttrs))
	for i, na := range nameAttrs {
		natmp, err = uncookNameAttr(na)
		if err != nil {
			return
		}
		args.NameAttrs[i] = natmp
	}
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intIMPORT_AND_CANON_NAME, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.OutputName) > 0 {
		ntmp, err = cookName(res.OutputName[0])
		if err != nil {
			return
		}
		cooked.Name = &ntmp
	}
	cooked.Options = res.Options

	results = cooked
	return
}

type ExportCredResults struct {
	Status         Status
	CredUsage      int
	ExportedHandle []byte
	Options        []Option
}

/* ExportCred converts a credential structure into a byte slice.  As of gss-proxy 0.3.1, the proxy implementation is a no-op. */
func ExportCred(conn *net.Conn, callCtx *CallCtx, cred Cred, credUsage int, options []Option) (results ExportCredResults, err error) {
	var args struct {
		CallCtx   CallCtx
		Cred      rawCred
		CredUsage int
		Options   []Option
	}
	var res struct {
		Status         rawStatus
		CredUsage      int
		ExportedHandle []byte
		Options        []Option
	}
	var cooked ExportCredResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.Cred, err = uncookCred(cred)
	if err != nil {
		return
	}
	args.CredUsage = credUsage
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intEXPORT_CRED, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	cooked.CredUsage = res.CredUsage
	cooked.ExportedHandle = res.ExportedHandle
	cooked.Options = res.Options

	results = cooked
	return
}

type ImportCredResults struct {
	Status           Status
	OutputCredHandle *Cred
	Options          []Option
}

/* ImportCred reconstructs a credential structure from a byte slice.  As of gss-proxy 0.3.1, the proxy implementation is a no-op. */
func ImportCred(conn *net.Conn, callCtx *CallCtx, exportedCred []byte, options []Option) (results ImportCredResults, err error) {
	var args struct {
		CallCtx      CallCtx
		ExportedCred []byte
		Options      []Option
	}
	var res struct {
		Status           rawStatus
		OutputCredHandle []rawCred
		Options          []Option
	}
	var cooked ImportCredResults
	var cbuf, rbuf bytes.Buffer
	var ctmp Cred

	args.CallCtx = *callCtx
	args.ExportedCred = exportedCred
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intIMPORT_CRED, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.OutputCredHandle) > 0 {
		ctmp, err = cookCred(res.OutputCredHandle[0])
		if err != nil {
			return
		}
		cooked.OutputCredHandle = &ctmp
	}
	cooked.Options = res.Options

	results = cooked
	return
}

type AcquireCredResults struct {
	Status           Status
	OutputCredHandle *Cred
	Options          []Option
}

/* AcquireCred adds non-default credentials, or credentials using non-default settings, to a credential structure, possibly creating one. */
func AcquireCred(conn *net.Conn, callCtx *CallCtx, inputCredHandle *Cred, addCredToInputHandle bool, desiredName *Name, timeReq uint64, desiredMechs []asn1.ObjectIdentifier, credUsage int, initiatorTimeReq, acceptorTimeReq uint64, options []Option) (results AcquireCredResults, err error) {
	var args struct {
		CallCtx                           CallCtx
		InputCredHandle                   []rawCred
		AddCredToInputHandle              bool
		DesiredName                       []rawName
		TimeReq                           uint64
		DesiredMechs                      [][]byte
		CredUsage                         int
		InitiatorTimeReq, AcceptorTimeReq uint64
		Options                           []Option
	}
	var res struct {
		Status           rawStatus
		OutputCredHandle []rawCred
		Options          []Option
	}
	var cooked AcquireCredResults
	var ctmp rawCred
	var cctmp Cred
	var ntmp rawName
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	if inputCredHandle != nil {
		args.InputCredHandle = make([]rawCred, 1)
		ctmp, err = uncookCred(*inputCredHandle)
		if err != nil {
			return
		}
		args.InputCredHandle[0] = ctmp
	} else {
		args.InputCredHandle = make([]rawCred, 0)
	}
	args.AddCredToInputHandle = addCredToInputHandle
	if desiredName != nil {
		args.DesiredName = make([]rawName, 1)
		ntmp, err = uncookName(*desiredName)
		if err != nil {
			return
		}
		args.DesiredName[0] = ntmp
	} else {
		args.DesiredName = make([]rawName, 0)
	}
	args.TimeReq = timeReq
	args.DesiredMechs = make([][]byte, len(desiredMechs))
	for i, m := range desiredMechs {
		args.DesiredMechs[i], err = uncookOid(m)
		if err != nil {
			return
		}
	}
	args.CredUsage = credUsage
	args.InitiatorTimeReq = initiatorTimeReq
	args.AcceptorTimeReq = acceptorTimeReq
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intACQUIRE_CRED, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.OutputCredHandle) > 0 {
		cctmp, err = cookCred(res.OutputCredHandle[0])
		if err != nil {
			return
		}
		cooked.OutputCredHandle = &cctmp
	}
	cooked.Options = res.Options

	results = cooked
	return
}

type StoreCredResults struct {
	Status          Status
	ElementsStored  []asn1.ObjectIdentifier
	CredUsageStored int
	Options         []Option
}

/* StoreCred stores credentials for a specific mechanism and which are intended for a specific use in the default credential store, optionally overwriting other credentials which may already be present, and also optionally making them the default credentials.  As of gss-proxy 0.3.1, the proxy implementation is a no-op. */
func StoreCred(conn *net.Conn, callCtx *CallCtx, cred Cred, credUsage int, desiredMech asn1.ObjectIdentifier, overwriteCred, defaultCred bool, options []Option) (results StoreCredResults, err error) {
	var args struct {
		CallCtx            CallCtx
		Cred               rawCred
		CredUsage          int
		DesiredMech        []byte
		Overwrite, Default bool
		Options            []Option
	}
	var res struct {
		Status          rawStatus
		ElementsStored  [][]byte
		CredUsageStored int
		Options         []Option
	}
	var cooked StoreCredResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.Cred, err = uncookCred(cred)
	if err != nil {
		return
	}
	args.CredUsage = credUsage
	args.DesiredMech, err = uncookOid(desiredMech)
	if err != nil {
		return
	}
	args.Overwrite = overwriteCred
	args.Default = defaultCred
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intSTORE_CRED, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	cooked.ElementsStored = make([]asn1.ObjectIdentifier, len(res.ElementsStored))
	for i, es := range res.ElementsStored {
		cooked.ElementsStored[i], err = cookOid(es)
		if err != nil {
			return
		}
	}
	cooked.CredUsageStored = res.CredUsageStored
	cooked.Options = res.Options

	results = cooked
	return
}

/* mechIsKerberos returns a boolean if the passed-in mech is any of three OIDs which we take to mean "Kerberos 5". */
func mechIsKerberos(mech asn1.ObjectIdentifier) bool {
	if mech.Equal(MechKerberos5) || mech.Equal(MechKerberos5Draft) || mech.Equal(MechKerberos5Wrong) {
		return true
	}
	return false
}

type InitSecContextResults struct {
	Status      Status
	SecCtx      *SecCtx
	OutputToken *[]byte
	Options     []Option
}

/* InitSecContext initiates a security context with a peer.  If the returned Status.MajorStatus is S_CONTINUE_NEEDED, the function should be called again with a token obtained from the peer.  If the OutputToken is not nil, then it should be sent to the peer.  If the returned Status.MajorStatus is S_COMPLETE, then authentication has succeeded.  Any other Status.MajorStatus value is an error. */
func InitSecContext(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, cred *Cred, targetName *Name, mechType asn1.ObjectIdentifier, reqFlags Flags, timeReq uint64, inputCB, inputToken *[]byte, options []Option) (results InitSecContextResults, err error) {
	var inct initialNegContextToken
	var resp negTokenResp
	var token []byte

	if len(mechType) == 0 || !mechType.Equal(MechSPNEGO) {
		if len(mechType) == 0 {
			mechType = mechKerberos5
		}
		return proxyInitSecContext(conn, callCtx, ctx, cred, targetName, mechType, reqFlags, timeReq, inputCB, inputToken, options)
	}

	if inputToken != nil {
		/* Parse a reply from the peer. */
		_, err = asn1.UnmarshalWithParams(*inputToken, &resp, "explicit,tag:1")
		if err != nil {
			return proxyInitSecContext(conn, callCtx, ctx, cred, targetName, mechType, reqFlags, timeReq, inputCB, inputToken, options)
		}
		/* Check that we're still okay. */
		if resp.NegState != negStateAcceptCompleted && resp.NegState != negStateAcceptIncomplete {
			results.Status.MajorStatus = S_BAD_STATUS
			results.Status.MajorStatusString = fmt.Sprintf("SPNEGO status %d not handled by this implementation", resp.NegState)
			return
		}
		/* If there's a mech indicated, check that it's one that we wanted. */
		if len(resp.SupportedMech) > 0 {
			if cred != nil && cred.negotiateMechs != nil && len(*cred.negotiateMechs) > 0 && (*cred.negotiateMechs)[0].Equal(resp.SupportedMech) {
				/* Not our preferred specified mech. */
				results.Status.MajorStatus = S_BAD_MECH
				results.Status.MajorStatusString = fmt.Sprintf("bad SPNEGO preferred mechanism [%s]", resp.SupportedMech)
				return
			} else {
				if !mechIsKerberos(resp.SupportedMech) {
					/* Not a Kerberos mech. */
					results.Status.MajorStatus = S_BAD_MECH
					results.Status.MajorStatusString = fmt.Sprintf("bad SPNEGO preferred mechanism [%s]", resp.SupportedMech)
					return
				} else {
					/* It's a mech that we wanted. */
					inputToken = &resp.ResponseToken
					mechType = resp.SupportedMech
				}
			}
		} else {
			/* Just assume it's the right mech and the proxy knows what to do with the inner token. */
			inputToken = &resp.ResponseToken
			mechType = defaultSPNEGOMechs[0]
		}
	} else {
		/* First time through, specify which mech to use. */
		if cred != nil && cred.negotiateMechs != nil && len(*cred.negotiateMechs) > 0 {
			mechType = (*cred.negotiateMechs)[0]
		} else {
			mechType = defaultSPNEGOMechs[0]
		}
	}
	/* Call the real mechanism. */
	results, err = proxyInitSecContext(conn, callCtx, ctx, cred, targetName, mechType, reqFlags, timeReq, inputCB, inputToken, options)
	if results.Status.MajorStatus != S_COMPLETE && results.Status.MajorStatus != S_CONTINUE_NEEDED {
		return
	}
	/* Don't advertise that we can do MICs yet if we don't know that the peer wants us to sign the negotiation. */
	if results.Status.MajorStatus == S_CONTINUE_NEEDED {
		results.SecCtx.Flags.ProtReady = false
	}
	if inputToken != nil {
		if resp.NegState == negStateAcceptCompleted && results.OutputToken != nil {
			/* Peer is not expecting more data, but we have some to send. */
			results.Status.MajorStatus = S_BAD_STATUS
			results.Status.MajorStatusString = "have SPNEGO data to send, but peer expects none"
			return
		}
		if resp.NegState == negStateAcceptIncomplete && results.OutputToken == nil {
			/* Peer is expecting more data, but we have none to send. */
			results.Status.MajorStatus = S_BAD_STATUS
			results.Status.MajorStatusString = "have no SPNEGO data to send, but peer expects some"
			return
		}
	}
	/* Create an SPNEGO token if there's data to send. */
	if results.OutputToken != nil {
		inct.ThisMech = MechSPNEGO
		if cred != nil && cred.negotiateMechs != nil && len(*cred.negotiateMechs) > 0 {
			inct.NegTokenInit.MechTypes = *cred.negotiateMechs
		} else {
			inct.NegTokenInit.MechTypes = defaultSPNEGOMechs
		}
		inct.NegTokenInit.MechToken = *results.OutputToken
		/* Encode the SPNEGO intiator. */
		if inputToken != nil {
			/* Second-or-later pass, don't include the mech OID framing. */
			token, err = asn1.Marshal(inct.NegTokenInit)
			if err != nil {
				return
			}
			/* Strip off the outermost sequence tag and add a context-specific one. */
			_, _, _, _, raw := splitTagAndLength(token)
			tl := makeTagAndLength(0xa0, len(raw))
			buf := bytes.NewBuffer(tl)
			buf.Write(raw)
			token = buf.Bytes()
		} else {
			/* First-pass, include the mech OID. */
			token, err = asn1.Marshal(inct)
			if err != nil {
				return
			}
			/* Strip off the outermost sequence tag and add an implicit application one. */
			_, _, _, _, raw := splitTagAndLength(token)
			tl := makeTagAndLength(0x60, len(raw))
			buf := bytes.NewBuffer(tl)
			buf.Write(raw)
			token = buf.Bytes()
		}
		results.OutputToken = &token
	}
	return
}
func proxyInitSecContext(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, cred *Cred, targetName *Name, mechType asn1.ObjectIdentifier, reqFlags Flags, timeReq uint64, inputCB, inputToken *[]byte, options []Option) (results InitSecContextResults, err error) {
	var args struct {
		CallCtx           CallCtx
		Ctx               []rawSecCtx
		Cred              []rawCred
		TargetName        []rawName
		MechType          []byte
		ReqFlags, TimeReq uint64
		InputCB           [][]byte
		InputToken        [][]byte
		Options           []Option
	}
	var res struct {
		Status      rawStatus
		Ctx         []rawSecCtx
		OutputToken [][]byte
		Options     []Option
	}
	var stmp rawSecCtx
	var sctmp SecCtx
	var ctmp rawCred
	var ntmp rawName
	var cooked InitSecContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	if ctx != nil && len(ctx.ExportedContextToken) > 0 {
		args.Ctx = make([]rawSecCtx, 1)
		stmp, err = uncookSecCtx(*ctx)
		if err != nil {
			return
		}
		args.Ctx[0] = stmp
	} else {
		args.Ctx = make([]rawSecCtx, 0)
	}
	if cred != nil {
		args.Cred = make([]rawCred, 1)
		ctmp, err = uncookCred(*cred)
		if err != nil {
			return
		}
		args.Cred[0] = ctmp
	} else {
		args.Cred = make([]rawCred, 0)
	}
	if targetName != nil {
		args.TargetName = make([]rawName, 1)
		ntmp, err = uncookName(*targetName)
		if err != nil {
			return
		}
		args.TargetName[0] = ntmp
	} else {
		args.TargetName = make([]rawName, 0)
	}
	if len(mechType) > 0 {
		args.MechType, err = uncookOid(mechType)
		if err != nil {
			return
		}
	}
	args.ReqFlags = uncookFlags(reqFlags)
	args.TimeReq = timeReq
	if inputCB != nil {
		args.InputCB = make([][]byte, 1)
		args.InputCB[0] = *inputCB
	} else {
		args.InputCB = make([][]byte, 0)
	}
	if inputToken != nil {
		args.InputToken = make([][]byte, 1)
		args.InputToken[0] = *inputToken
	} else {
		args.InputToken = make([][]byte, 0)
	}
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intINIT_SEC_CONTEXT, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.Ctx) > 0 {
		sctmp, err = cookSecCtx(res.Ctx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	if len(res.OutputToken) > 0 {
		cooked.OutputToken = &res.OutputToken[0]
	}
	cooked.Options = res.Options

	results = cooked
	return
}

type AcceptSecContextResults struct {
	Status              Status
	SecCtx              *SecCtx
	OutputToken         *[]byte
	DelegatedCredHandle *Cred
	Options             []Option
}

/* AcceptSecContext accepts a security context initiated by a peer.  If the returned Status.MajorStatus is S_CONTINUE_NEEDED, the function should be called again with a token obtained from the peer.  If the OutputToken is not nil, then it should be sent to the peer.  If the returned Status.MajorStatus is S_COMPLETE, then authentication has succeeded.  Any other Status.MajorStatus value is an error. */
func AcceptSecContext(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, cred *Cred, inputToken []byte, inputCB *[]byte, retDelegCred bool, options []Option) (results AcceptSecContextResults, err error) {
	var inct initialNegContextToken
	var resp negotiateResp
	var token []byte

	/* Try to parse it as an SPNEGO initiator token. */
	_, err = asn1.UnmarshalWithParams(inputToken, &ict, "application,tag:0")
	if err != nil || !ict.ThisMech.Equal(MechSPNEGO) || len(ict.NegTokenInit.MechTypes) == 0 {
		_, err = asn1.UnmarshalWithParams(inputToken, &ict.NegTokenInit, "tag:0")
		if err != nil {
			return proxyAcceptSecContext(conn, callCtx, ctx, cred, inputToken, inputCB, retDelegCred, options)
		}
	}
	/* Check if the client's requested one of our preferred mechanisms. */
	preferredMech := ict.NegTokenInit.MechTypes[0]
	if len(preferredMech) == 0 || mechIsKerberos(preferredMech) {
		/* Pass the mechanism-specific token on to the proxy. */
		results, err = proxyAcceptSecContext(conn, callCtx, ctx, cred, ict.NegTokenInit.MechToken, inputCB, retDelegCred, options)
		if err == nil {
			/* Interpret the proxy's result. */
			if results.Status.MajorStatus == S_COMPLETE {
				resp.NegTokenResp.NegState = negStateAcceptCompleted
				if len(preferredMech) == 0 {
					preferredMech = results.SecCtx.Mech
				}
			} else if results.Status.MajorStatus == S_CONTINUE_NEEDED {
				resp.NegTokenResp.NegState = negStateAcceptIncomplete
			} else {
				resp.NegTokenResp.NegState = negStateReject
			}
			/* Set things up to encapsulate the mech reply. */
			if len(preferredMech) != 0 {
				resp.NegTokenResp.SupportedMech = preferredMech
			} else {
				resp.NegTokenResp.SupportedMech = MechKerberos5
			}
			if results.OutputToken != nil {
				resp.NegTokenResp.ResponseToken = *results.OutputToken
			}
		} else {
			/* Don't return an SPNEGO error token, but indicate an error. */
			results.OutputToken = nil
			results.Status.MajorStatus = S_FAILURE
			results.Status.MajorStatusString = "internal error in SPNEGO"
			return
		}
	} else {
		/* Return an SPNEGO error. */
		results.Status.MajorStatus = S_BAD_MECH
		results.Status.MajorStatusString = fmt.Sprintf("bad SPNEGO preferred mechanism [%s]", ict.NegTokenInit.MechTypes[0])
		resp.NegTokenResp.NegState = negStateReject
	}
	/* Encode the SPNEGO reply; we always send data back. */
	token, err = asn1.Marshal(resp)
	results.OutputToken = nil
	if err != nil {
		results.Status.MajorStatus = S_FAILURE
		results.Status.MajorStatusString = "internal error in SPNEGO"
		return
	}
	/* Strip off the outermost sequence tag. */
	_, _, _, _, raw := splitTagAndLength(token)
	results.OutputToken = &raw
	return
}
func proxyAcceptSecContext(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, cred *Cred, inputToken []byte, inputCB *[]byte, retDelegCred bool, options []Option) (results AcceptSecContextResults, err error) {
	var args struct {
		CallCtx      CallCtx
		Ctx          []rawSecCtx
		Cred         []rawCred
		InputToken   []byte
		InputCB      [][]byte
		RetDelegCred bool
		Options      []Option
	}
	var res struct {
		Status              rawStatus
		Ctx                 []rawSecCtx
		OutputToken         [][]byte
		DelegatedCredHandle []rawCred
		Options             []Option
	}
	var stmp rawSecCtx
	var sctmp SecCtx
	var ctmp rawCred
	var dctmp Cred
	var cooked AcceptSecContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	if ctx != nil && len(ctx.ExportedContextToken) > 0 {
		args.Ctx = make([]rawSecCtx, 1)
		stmp, err = uncookSecCtx(*ctx)
		if err != nil {
			return
		}
		args.Ctx[0] = stmp
	} else {
		args.Ctx = make([]rawSecCtx, 0)
	}
	if cred != nil {
		args.Cred = make([]rawCred, 1)
		ctmp, err = uncookCred(*cred)
		if err != nil {
			return
		}
		args.Cred[0] = ctmp
	} else {
		args.Cred = make([]rawCred, 0)
	}
	args.InputToken = inputToken
	if inputCB != nil {
		args.InputCB = make([][]byte, 1)
		args.InputCB[0] = *inputCB
	} else {
		args.InputCB = make([][]byte, 0)
	}
	args.RetDelegCred = retDelegCred
	args.Options = options
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intACCEPT_SEC_CONTEXT, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.Ctx) > 0 {
		sctmp, err = cookSecCtx(res.Ctx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	if len(res.OutputToken) > 0 {
		cooked.OutputToken = &res.OutputToken[0]
	}
	if len(res.DelegatedCredHandle) > 0 {
		dctmp, err = cookCred(res.DelegatedCredHandle[0])
		if err != nil {
			return
		}
		cooked.DelegatedCredHandle = &dctmp
	}
	cooked.Options = res.Options

	results = cooked
	return
}

type ReleaseCredResults struct {
	Status Status
}

/* ReleaseCred releases credentials which will no longer be needed. */
func ReleaseCred(conn *net.Conn, callCtx *CallCtx, cred *Cred) (results ReleaseCredResults, err error) {
	var args struct {
		CallCtx CallCtx
		What    int
		Cred    rawCred
	}
	var res struct {
		Status rawStatus
	}
	var cooked ReleaseCredResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.What = intGSSX_C_HANDLE_CRED
	args.Cred, err = uncookCred(*cred)
	if err != nil {
		return
	}
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intRELEASE_HANDLE, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	results = cooked
	return
}

type ReleaseSecCtxResults struct {
	Status Status
}

/* ReleaseSecCtx releases a security context which will no longer be needed. */
func ReleaseSecCtx(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx) (results ReleaseSecCtxResults, err error) {
	var args struct {
		CallCtx CallCtx
		What    int
		SecCtx  rawSecCtx
	}
	var res struct {
		Status rawStatus
	}
	var cooked ReleaseSecCtxResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.What = intGSSX_C_HANDLE_SEC_CTX
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intRELEASE_HANDLE, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	results = cooked
	return
}

type GetMicResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer []byte
	QopState    uint64
}

/* GetMic computes an integrity checksum over the passed-in message and returns the checksum.  If a SecCtx is returned, then the passed-in ctx value should be discarded in its favor. */
func GetMic(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, qopReq uint64, message []byte) (results GetMicResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		QopReq        uint64
		MessageBuffer []byte
	}
	var res struct {
		Status      rawStatus
		SecCtx      []rawSecCtx
		TokenBuffer []byte
		QopState    []uint64
	}
	var sctmp SecCtx
	var cooked GetMicResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	args.QopReq = qopReq
	args.MessageBuffer = message
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intGET_MIC, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.SecCtx) > 0 {
		sctmp, err = cookSecCtx(res.SecCtx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	cooked.TokenBuffer = res.TokenBuffer
	if len(res.QopState) > 0 {
		cooked.QopState = res.QopState[0]
	}

	results = cooked
	return
}

type VerifyMicResults struct {
	Status   Status
	SecCtx   *SecCtx
	QopState uint64
}

/* VerifyMic checks an already-computed integrity checksum over the passed-in plaintext.  If a SecCtx is returned, then the passed-in ctx value should be discarded in its favor. */
func VerifyMic(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, messageBuffer, tokenBuffer []byte) (results VerifyMicResults, err error) {
	var args struct {
		CallCtx                    CallCtx
		SecCtx                     rawSecCtx
		MessageBuffer, TokenBuffer []byte
	}
	var res struct {
		Status   rawStatus
		SecCtx   []rawSecCtx
		QopState []uint64
	}
	var sctmp SecCtx
	var cooked VerifyMicResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	args.MessageBuffer = messageBuffer
	args.TokenBuffer = tokenBuffer
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intVERIFY, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.SecCtx) > 0 {
		sctmp, err = cookSecCtx(res.SecCtx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	if len(res.QopState) > 0 {
		cooked.QopState = res.QopState[0]
	}

	results = cooked
	return
}

type WrapResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer [][]byte
	ConfState   bool
	QopState    uint64
}

/* Wrap applies protection to plaintext, optionally using confidentiality, and returns a suitably encapsulated copy of the plaintext.  If a SecCtx is returned, then the passed-in ctx value should be discarded in its favor. */
func Wrap(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, confReq bool, message [][]byte, qopState uint64) (results WrapResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		ConfReq       bool
		MessageBuffer [][]byte
		QopState      uint64
	}
	var res struct {
		Status      rawStatus
		SecCtx      []rawSecCtx
		TokenBuffer [][]byte
		ConfState   []bool
		QopState    []uint64
	}
	var sctmp SecCtx
	var cooked WrapResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	args.ConfReq = confReq
	args.MessageBuffer = message
	args.QopState = qopState
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intWRAP, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.SecCtx) > 0 {
		sctmp, err = cookSecCtx(res.SecCtx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	cooked.TokenBuffer = res.TokenBuffer
	if len(res.ConfState) > 0 {
		cooked.ConfState = res.ConfState[0]
	}
	if len(res.QopState) > 0 {
		cooked.QopState = res.QopState[0]
	}

	results = cooked
	return
}

type UnwrapResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer [][]byte
	ConfState   bool
	QopState    uint64
}

/* Unwrap verifies protection on plaintext, optionally removing a confidentiality layer, and returns the plaintext.  If a SecCtx is returned, then the passed-in ctx value should be discarded in its favor. */
func Unwrap(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, message [][]byte, qopReq uint64) (results UnwrapResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		MessageBuffer [][]byte
		QopReq        uint64
	}
	var res struct {
		Status      rawStatus
		SecCtx      []rawSecCtx
		TokenBuffer [][]byte
		ConfState   []bool
		QopState    []uint64
	}
	var sctmp SecCtx
	var cooked UnwrapResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	args.MessageBuffer = message
	args.QopReq = qopReq
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intUNWRAP, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	if len(res.SecCtx) > 0 {
		sctmp, err = cookSecCtx(res.SecCtx[0])
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
		if ctx != nil {
			*ctx = sctmp
		}
	}
	cooked.TokenBuffer = res.TokenBuffer
	if len(res.ConfState) > 0 {
		cooked.ConfState = res.ConfState[0]
	}
	if len(res.QopState) > 0 {
		cooked.QopState = res.QopState[0]
	}

	results = cooked
	return
}

type WrapSizeLimitResults struct {
	Status       Status
	MaxInputSize uint64
}

/* WrapSizeLimit computes the maximum size of a message that can be wrapped if the resulting message token is to be at most reqOutputSize bytes in length. */
func WrapSizeLimit(conn *net.Conn, callCtx *CallCtx, ctx *SecCtx, confReq bool, qopReq, reqOutputSize uint64) (results WrapSizeLimitResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		ConfReq       bool
		QopReq        uint64
		ReqOutputSize uint64
	}
	var res struct {
		Status       rawStatus
		MaxInputSize uint64
	}
	var cooked WrapSizeLimitResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = *callCtx
	args.SecCtx, err = uncookSecCtx(*ctx)
	if err != nil {
		return
	}
	args.ConfReq = confReq
	args.QopReq = qopReq
	args.ReqOutputSize = reqOutputSize
	_, err = xdr.Marshal(&cbuf, &args)
	if err != nil {
		return
	}

	err = CallRpc(conn, intGSSPROXY_PROG, intGSSPROXY_VERS, intWRAP_SIZE_LIMIT, AUTH_NONE, cbuf.Bytes(), &rbuf)
	if err != nil {
		return
	}

	_, err = xdr.Unmarshal(&rbuf, &res)
	if err != nil {
		return
	}
	cooked.Status, err = cookStatus(res.Status)
	if err != nil {
		return
	}
	callCtx.ServerCtx = cooked.Status.ServerCtx

	cooked.MaxInputSize = res.MaxInputSize

	results = cooked
	return
}

type SetNegMechsResults struct {
	Status  Status
	Options []Option
}

/* SetNegMechs sets the list of mechanisms which will be offered if we attempt to initialize a security context using the SPNEGO mechanism. */
func SetNegMechs(conn *net.Conn, callCtx *CallCtx, cred *Cred, mechTypes *[]asn1.ObjectIdentifier) (results SetNegMechsResults, err error) {
	cred.negotiateMechs = mechTypes
	results.Status.ServerCtx = callCtx.ServerCtx
	return
}
