package proxy

import "bytes"
import "encoding/asn1"
import "net"
import "github.com/davecgh/go-xdr/xdr2"

const (
	intGSSPROXY_PROG = 400112
	intGSSPROXY_VERS = 1

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

	/* Credential Usage values to be passed to ExportCred() and StoreCred(). */
	GSSX_C_INITIATE = 1
	GSSX_C_ACCEPT   = 2
	GSSX_C_BOTH     = 3

	intGSSX_C_HANDLE_SEC_CTX = 0
	intGSSX_C_HANDLE_CRED    = 1
)

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

type NameAttr struct {
	Attr, Value []byte
	Extensions  []Option
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
	NameAttributes                                []NameAttr
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
	raw.DisplayName = n.DisplayName
	raw.NameType, err = uncookOid(n.NameType)
	if err != nil {
		return
	}
	raw.ExportedName = n.ExportedName
	raw.ExportedCompositeName = n.ExportedCompositeName
	raw.NameAttributes = n.NameAttributes
	raw.Extensions = n.Extensions
	return
}

func cookName(n rawName) (cooked Name, err error) {
	cooked.DisplayName = n.DisplayName
	cooked.NameType, err = cookOid(n.NameType)
	if err != nil {
		return
	}
	cooked.ExportedName = n.ExportedName
	cooked.ExportedCompositeName = n.ExportedCompositeName
	cooked.NameAttributes = n.NameAttributes
	cooked.Extensions = n.Extensions
	return
}

type rawCredElement struct {
	MN, Mech                          []byte
	CredUsage                         uint32
	InitiatorTimeRec, AcceptorTimeRec uint64
	Options                           []Option
}

type CredElement struct {
	MN                                []byte
	Mech                              asn1.ObjectIdentifier
	CredUsage                         int
	InitiatorTimeRec, AcceptorTimeRec uint64
	Options                           []Option
}

func uncookCredElement(ce CredElement) (raw rawCredElement, err error) {
	raw.MN = ce.MN
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
	cooked.MN = c.MN
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
	Lifetime, CtxFlags          uint64
	LocallyInitiated, Open      bool
	Options                     []Option
}

func uncookSecCtx(s SecCtx) (raw rawSecCtx, err error) {
	raw.ExportedContextToken = raw.ExportedContextToken
	raw.NeedsRelease = raw.NeedsRelease
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
	raw.CtxFlags = s.CtxFlags
	raw.LocallyInitiated = s.LocallyInitiated
	raw.Open = s.Open
	raw.Options = s.Options
	return
}

func cookSecCtx(c rawSecCtx) (cooked SecCtx, err error) {
	cooked.ExportedContextToken = c.ExportedContextToken
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
	cooked.CtxFlags = c.CtxFlags
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
func IndicateMechs(conn *net.Conn, callCtx CallCtx) (results IndicateMechsResults, err error) {
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

	args.CallCtx = callCtx
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

/* GetCallContext returns a ServerCtx value which should be used in subsequent calls to this proxy server. */
func GetCallContext(conn *net.Conn, callCtx CallCtx, options []Option) (results GetCallContextResults, err error) {
	var args struct {
		CallCtx CallCtx
		Options []Option
	}
	var res GetCallContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
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

	results = res
	return
}

type ImportAndCanonNameResults struct {
	Status  Status
	Name    Name
	Options []Option
}

/* ImportAndCanonName imports and canonicalizes a name. */
func ImportAndCanonName(conn *net.Conn, callCtx CallCtx, name Name, mech asn1.ObjectIdentifier, nameAttrs []NameAttr, options []Option) (results ImportAndCanonNameResults, err error) {
	var args struct {
		CallCtx   CallCtx
		Name      rawName
		NameAttrs []NameAttr
		Mech      []byte
		Options   []Option
	}
	var res ImportAndCanonNameResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	args.Name, err = uncookName(name)
	if err != nil {
		return
	}
	args.Mech, err = uncookOid(mech)
	if err != nil {
		return
	}
	args.NameAttrs = nameAttrs
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

	results = res
	return
}

type ExportCredResults struct {
	Status    Status
	CredUsage int
	Exported  []byte
	Options   []Option
}

/* ExportCred converts a credential structure into a byte slice. */
func ExportCred(conn *net.Conn, callCtx CallCtx, cred Cred, credUsage int, options []Option) (results ExportCredResults, err error) {
	var args struct {
		CallCtx   CallCtx
		Cred      rawCred
		CredUsage int
		Options   []Option
	}
	var res ExportCredResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
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

	results = res
	return
}

type ImportCredResults struct {
	Status  Status
	Cred    Cred
	Options []Option
}

/* ImportCred constructs a credential structure from a byte slice. */
func ImportCred(conn *net.Conn, callCtx CallCtx, exportedCred []byte, options []Option) (results ImportCredResults, err error) {
	var args struct {
		CallCtx      CallCtx
		ExportedCred []byte
		Options      []Option
	}
	var res ImportCredResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
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

	results = res
	return
}

type StoreCredResults struct {
	Status          Status
	ElementsStored  []asn1.ObjectIdentifier
	CredUsageStored int
	Options         []Option
}

/* StoreCred stores credentials for a specific mechanism and which are intended for a specific use in the default credential store, optionally overwriting other credentials which may already be present, and also optionally making them the default credentials. */
func StoreCred(conn *net.Conn, callCtx CallCtx, cred Cred, credUsage int, desiredMech asn1.ObjectIdentifier, overwriteCred, defaultCred bool, options []Option) (results StoreCredResults, err error) {
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

	args.CallCtx = callCtx
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

type InitSecContextResults struct {
	Status      Status
	Ctx         *SecCtx
	OutputToken *[]byte
	Options     []Option
}

/* InitSecContext initiates a security context with a peer. */
func InitSecContext(conn *net.Conn, callCtx CallCtx, ctx *SecCtx, cred *Cred, targetName *Name, mechType asn1.ObjectIdentifier, reqFlags, timeReq uint64, inputToken *[]byte, options []Option) (results InitSecContextResults, err error) {
	var args struct {
		CallCtx           CallCtx
		Ctx               *rawSecCtx
		Cred              *rawCred
		TargetName        *rawName
		MechType          []byte
		ReqFlags, TimeReq uint64
		InputCB           []byte
		InputToken        *[]byte
		Options           []Option
	}
	var res struct {
		Status      rawStatus
		Ctx         *rawSecCtx
		OutputToken *[]byte
		Options     []Option
	}
	var stmp rawSecCtx
	var sctmp SecCtx
	var ctmp rawCred
	var ntmp rawName
	var cooked InitSecContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	if ctx != nil {
		stmp, err = uncookSecCtx(*ctx)
		if err != nil {
			return
		}
		args.Ctx = &stmp
	}
	if cred != nil {
		ctmp, err = uncookCred(*cred)
		if err != nil {
			return
		}
		args.Cred = &ctmp
	}
	if targetName != nil {
		ntmp, err = uncookName(*targetName)
		if err != nil {
			return
		}
		args.TargetName = &ntmp
	}
	args.MechType, err = uncookOid(mechType)
	if err != nil {
		return
	}
	args.ReqFlags = reqFlags
	args.TimeReq = timeReq
	args.InputToken = inputToken
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
	if res.Ctx != nil {
		sctmp, err = cookSecCtx(*res.Ctx)
		if err != nil {
			return
		}
		cooked.Ctx = &sctmp
	}
	cooked.OutputToken = res.OutputToken
	cooked.Options = res.Options

	results = cooked
	return
}

type AcceptSecContextResults struct {
	Status              Status
	Ctx                 *SecCtx
	OutputToken         *[]byte
	DelegatedCredHandle *Cred
	Options             []Option
}

/* AcceptSecContext accepts a security context initiated by a peer. */
func AcceptSecContext(conn *net.Conn, callCtx CallCtx, ctx *SecCtx, cred *Cred, inputToken *[]byte, retDelegCred bool, options []Option) (results AcceptSecContextResults, err error) {
	var args struct {
		CallCtx      CallCtx
		Ctx          *rawSecCtx
		Cred         *rawCred
		InputToken   *[]byte
		InputCB      []byte
		RetDelegCred bool
		Options      []Option
	}
	var res struct {
		Status              rawStatus
		Ctx                 *rawSecCtx
		OutputToken         *[]byte
		DelegatedCredHandle *rawCred
		Options             []Option
	}
	var stmp rawSecCtx
	var sctmp SecCtx
	var ctmp rawCred
	var dctmp Cred
	var cooked AcceptSecContextResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	if ctx != nil {
		stmp, err = uncookSecCtx(*ctx)
		if err != nil {
			return
		}
		args.Ctx = &stmp
	}
	if cred != nil {
		ctmp, err = uncookCred(*cred)
		if err != nil {
			return
		}
		args.Cred = &ctmp
	}
	args.InputToken = inputToken
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
	if res.Ctx != nil {
		sctmp, err = cookSecCtx(*res.Ctx)
		if err != nil {
			return
		}
		cooked.Ctx = &sctmp
	}
	cooked.OutputToken = res.OutputToken
	if res.DelegatedCredHandle != nil {
		dctmp, err = cookCred(*res.DelegatedCredHandle)
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
func ReleaseCred(conn *net.Conn, callCtx CallCtx, cred Cred) (results ReleaseCredResults, err error) {
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

	args.CallCtx = callCtx
	args.What = intGSSX_C_HANDLE_CRED
	args.Cred, err = uncookCred(cred)
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

	results = cooked
	return
}

type ReleaseSecCtxResults struct {
	Status Status
}

/* ReleaseSecCtx releases a security context which will no longer be needed. */
func ReleaseSecCtx(conn *net.Conn, callCtx CallCtx, ctx SecCtx) (results ReleaseSecCtxResults, err error) {
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

	args.CallCtx = callCtx
	args.What = intGSSX_C_HANDLE_SEC_CTX
	args.SecCtx, err = uncookSecCtx(ctx)
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

	results = cooked
	return
}

type GetMicResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer []byte
	QopState    uint64
}

/* GetMic computes an integrity checksum over the passed-in message. */
func GetMic(conn *net.Conn, callCtx CallCtx, ctx SecCtx, qopReq uint64, message []byte) (results GetMicResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		QopReq        uint64
		MessageBuffer []byte
	}
	var res struct {
		Status      rawStatus
		SecCtx      *rawSecCtx
		TokenBuffer []byte
		QopState    *uint64
	}
	var sctmp SecCtx
	var cooked GetMicResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	args.SecCtx, err = uncookSecCtx(ctx)
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
	if res.SecCtx != nil {
		sctmp, err = cookSecCtx(*res.SecCtx)
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
	}
	cooked.TokenBuffer = res.TokenBuffer
	if res.QopState != nil {
		cooked.QopState = *res.QopState
	}

	results = cooked
	return
}

type VerifyMicResults struct {
	Status   Status
	SecCtx   *SecCtx
	QopState uint64
}

/* VerifyMic checks an already-computed integrity checksum over the passed-in message. */
func VerifyMic(conn *net.Conn, callCtx CallCtx, ctx SecCtx, qopReq uint64, messageBuffer, tokenBuffer []byte) (results VerifyMicResults, err error) {
	var args struct {
		CallCtx                    CallCtx
		SecCtx                     rawSecCtx
		QopReq                     uint64
		MessageBuffer, TokenBuffer []byte
	}
	var res struct {
		Status   rawStatus
		SecCtx   *rawSecCtx
		QopState *uint64
	}
	var sctmp SecCtx
	var cooked VerifyMicResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	args.SecCtx, err = uncookSecCtx(ctx)
	if err != nil {
		return
	}
	args.QopReq = qopReq
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
	if res.SecCtx != nil {
		sctmp, err = cookSecCtx(*res.SecCtx)
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
	}
	if res.QopState != nil {
		cooked.QopState = *res.QopState
	}

	results = cooked
	return
}

type WrapResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer []byte
	ConfState   bool
	QopState    uint64
}

/* Wrap applies protection to plaintext, optionally using confidentiality. */
func Wrap(conn *net.Conn, callCtx CallCtx, ctx SecCtx, confReq bool, message []byte, qopReq uint64) (results WrapResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		ConfReq       bool
		MessageBuffer []byte
		QopReq        uint64
	}
	var res struct {
		Status      rawStatus
		SecCtx      *rawSecCtx
		TokenBuffer []byte
		ConfState   *bool
		QopState    *uint64
	}
	var sctmp SecCtx
	var cooked WrapResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	args.SecCtx, err = uncookSecCtx(ctx)
	if err != nil {
		return
	}
	args.ConfReq = confReq
	args.MessageBuffer = message
	args.QopReq = qopReq
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
	if res.SecCtx != nil {
		sctmp, err = cookSecCtx(*res.SecCtx)
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
	}
	cooked.TokenBuffer = res.TokenBuffer
	if res.ConfState != nil {
		cooked.ConfState = *res.ConfState
	}
	if res.QopState != nil {
		cooked.QopState = *res.QopState
	}

	results = cooked
	return
}

type UnwrapResults struct {
	Status      Status
	SecCtx      *SecCtx
	TokenBuffer []byte
	ConfState   bool
	QopState    uint64
}

/* Unwrap verifies protection on plaintext, optionally removing a confidentiality layer. */
func Unwrap(conn *net.Conn, callCtx CallCtx, ctx SecCtx, message []byte, qopReq uint64) (results UnwrapResults, err error) {
	var args struct {
		CallCtx       CallCtx
		SecCtx        rawSecCtx
		MessageBuffer []byte
		QopReq        uint64
	}
	var res struct {
		Status      rawStatus
		SecCtx      *rawSecCtx
		TokenBuffer []byte
		ConfState   *bool
		QopState    *uint64
	}
	var sctmp SecCtx
	var cooked UnwrapResults
	var cbuf, rbuf bytes.Buffer

	args.CallCtx = callCtx
	args.SecCtx, err = uncookSecCtx(ctx)
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
	if res.SecCtx != nil {
		sctmp, err = cookSecCtx(*res.SecCtx)
		if err != nil {
			return
		}
		cooked.SecCtx = &sctmp
	}
	cooked.TokenBuffer = res.TokenBuffer
	if res.ConfState != nil {
		cooked.ConfState = *res.ConfState
	}
	if res.QopState != nil {
		cooked.QopState = *res.QopState
	}

	results = cooked
	return
}

type WrapSizeLimitResults struct {
	Status       Status
	MaxInputSize uint64
}

/* WrapSizeLimit computes the maximum size of a message that can be wrapped if the resulting message token is to be at most reqOutputSize bytes in length. */
func WrapSizeLimit(conn *net.Conn, callCtx CallCtx, ctx SecCtx, confReq bool, qopReq, reqOutputSize uint64) (results WrapSizeLimitResults, err error) {
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

	args.CallCtx = callCtx
	args.SecCtx, err = uncookSecCtx(ctx)
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
	cooked.MaxInputSize = res.MaxInputSize

	results = cooked
	return
}
