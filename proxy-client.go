package main

import "bytes"
import "flag"
import "encoding/asn1"
import "fmt"
import "gss/proxy"
import "gss/misc"
import "io"
import "net"
import "os"
import "strconv"
import "strings"

func displayStatus(when string, status proxy.Status) {
	fmt.Printf("Error \"%s\" ", status.MajorStatusString)
	if len(when) > 0 {
		fmt.Printf("while %s", when)
	}
	if len(status.MinorStatusString) > 0 {
		fmt.Printf(" (%s)", status.MinorStatusString)
	}
	fmt.Printf(".\n")
}

func displayFlags(flags proxy.Flags, complete bool, file io.Writer) {
	if flags.Deleg {
		fmt.Fprintf(file, "context flag: GSS_C_DELEG_FLAG\n")
	}
	if flags.DelegPolicy {
		fmt.Fprintf(file, "context flag: GSS_C_DELEG_POLICY_FLAG\n")
	}
	if flags.Mutual {
		fmt.Fprintf(file, "context flag: GSS_C_MUTUAL_FLAG\n")
	}
	if flags.Replay {
		fmt.Fprintf(file, "context flag: GSS_C_REPLAY_FLAG\n")
	}
	if flags.Sequence {
		fmt.Fprintf(file, "context flag: GSS_C_SEQUENCE_FLAG\n")
	}
	if flags.Anon {
		fmt.Fprintf(file, "context flag: GSS_C_ANON_FLAG\n")
	}
	if flags.Conf {
		fmt.Fprintf(file, "context flag: GSS_C_CONF_FLAG \n")
	}
	if flags.Integ {
		fmt.Fprintf(file, "context flag: GSS_C_INTEG_FLAG \n")
	}
	if complete {
		if flags.Trans {
			fmt.Fprintf(file, "context flag: GSS_C_TRANS_FLAG \n")
		}
		if flags.ProtReady {
			fmt.Fprintf(file, "context flag: GSS_C_PROT_READY_FLAG \n")
		}
	}
}

func connectOnce(pconn *net.Conn, pcc proxy.CallCtx, host string, port int, service string, mcount int, quiet bool, plain []byte, v1 bool, nmech *asn1.ObjectIdentifier, mech asn1.ObjectIdentifier, delegate, seq, noreplay, nomutual, noauth, nowrap, noenc, nomic bool) {
	var ctx proxy.SecCtx
	var pctx *proxy.SecCtx
	var status proxy.Status
	var tag byte
	var ptoken *[]byte
	var major, minor uint64
	var sname proxy.Name
	var localstate, openstate string
	var flags proxy.Flags

	/* Open the connection. */
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("Error connecting: %s\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	/* Import the remote service's name. */
	if strings.Contains(service, "@") {
		sname.DisplayName = service
	} else {
		sname.DisplayName = service + "@" + host
	}
	sname.NameType = proxy.NT_HOSTBASED_SERVICE
	icnr, err := proxy.ImportAndCanonName(pconn, pcc, sname, *nmech, nil, nil)
	if err != nil {
		fmt.Printf("Error importing remote service name: %s\n", err)
		return
	}
	if icnr.Status.MajorStatus != 0 {
		displayStatus("importing remote service name", icnr.Status)
		return
	}
	sname = *icnr.Name
	pcc.ServerCtx = icnr.Status.ServerCtx

	if noauth {
		misc.SendToken(conn, misc.TOKEN_NOOP, nil)
	} else {
		if !v1 {
			misc.SendToken(conn, misc.TOKEN_NOOP|misc.TOKEN_CONTEXT_NEXT, nil)
		}
		flags = proxy.Flags{Deleg: delegate, Sequence: seq, Replay: !noreplay, Conf: !noenc, Integ: !nomic, Mutual: !nomutual}
		for true {
			/* Start/continue. */
			iscr, err := proxy.InitSecContext(pconn, pcc, pctx, nil, &sname, mech, flags, proxy.C_INDEFINITE, ptoken, nil)
			if err != nil {
				fmt.Printf("Error initializing security context: %s\n", err)
				return
			}
			status = iscr.Status
			major = status.MajorStatus
			if major != proxy.S_COMPLETE && major != proxy.S_CONTINUE_NEEDED {
				displayStatus("initializing security context", iscr.Status)
				return
			}
			pcc.ServerCtx = iscr.Status.ServerCtx
			if iscr.SecCtx != nil {
				ctx = *iscr.SecCtx
				pctx = &ctx
			}
			/* If we have an output token, we need to send it. */
			if iscr.OutputToken != nil {
				if !quiet {
					fmt.Printf("Sending init_sec_context token (size=%d)...", len(*iscr.OutputToken))
				}
				if v1 {
					tag = 0
				} else {
					tag = misc.TOKEN_CONTEXT
				}
				misc.SendToken(conn, tag, *iscr.OutputToken)
			}
			if major == proxy.S_CONTINUE_NEEDED {
				/* CONTINUE_NEEDED means we expect a token from the far end to be fed back in to InitSecContext(). */
				var token []byte
				if !quiet {
					fmt.Printf("continue needed...")
				}
				tag, token = misc.RecvToken(conn)
				if !quiet {
					fmt.Printf("\n")
				}
				if len(token) == 0 {
					if !quiet {
						fmt.Printf("server closed connection.\n")
					}
					break
				}
				ptoken = &token
			} else {
				/* COMPLETE means we're done, everything succeeded. */
				if !quiet {
					fmt.Printf("\n")
				}
				break
			}
		}
		if major != proxy.S_COMPLETE {
			fmt.Printf("Error authenticating to server: %08x/%08x.\n", major, minor)
			return
		}
		if !quiet {
			displayFlags(flags, false, os.Stdout)
		}

		/* Describe the context. */
		if ctx.LocallyInitiated {
			localstate = "locally initiated"
		} else {
			localstate = "remotely initiated"
		}
		if ctx.Open {
			openstate = "open"
		} else {
			openstate = "closed"
		}
		if !quiet {
			fmt.Printf("\"%s\" to \"%s\", lifetime %d, flags %x, %s, %s\n", ctx.SrcName.DisplayName, ctx.TargName.DisplayName, ctx.Lifetime, proxy.FlagsToRaw(ctx.Flags), localstate, openstate)
		}
		if !quiet {
			fmt.Printf("Name type of source name is %s.\n", ctx.SrcName.NameType.String())
		}

		imr, err := proxy.IndicateMechs(pconn, pcc)
		if err != nil {
			fmt.Printf("Error indicating mechanisms: %s\n", err)
			return
		}
		status = imr.Status
		major = status.MajorStatus
		if major != proxy.S_COMPLETE && major != proxy.S_CONTINUE_NEEDED {
			displayStatus("indicating mechanisms", imr.Status)
			return
		}
		pcc.ServerCtx = imr.Status.ServerCtx

		for _, mech := range imr.Mechs {
			if !mech.Mech.Equal(ctx.Mech) {
				continue
			}
			if !quiet {
				fmt.Printf("Mechanism %s supports %d names\n", mech.Mech, len(mech.NameTypes))
			}
			for i, nametype := range mech.NameTypes {
				if !quiet {
					fmt.Printf("%3d: %s\n", i, nametype.String())
				}
			}
		}
	}

	for i := 0; i < mcount; i++ {
		var wrapped []byte
		var major uint64

		if nowrap {
			wrapped = plain
		} else {
			plains := make([][]byte, 1)
			plains[0] = plain
			wr, err := proxy.Wrap(pconn, pcc, ctx, !noenc, plains, proxy.C_QOP_DEFAULT)
			if err != nil {
				fmt.Printf("Error wrapping message: %s\n", err)
				return
			}
			status = wr.Status
			major = status.MajorStatus
			if major != proxy.S_COMPLETE {
				displayStatus("wrapping data", status)
				return
			}
			if !noenc && !wr.ConfState && !quiet {
				fmt.Printf("Warning!  Message not encrypted.\n")
			}
			pcc.ServerCtx = wr.Status.ServerCtx
			if wr.SecCtx != nil {
				ctx = *wr.SecCtx
				pctx = &ctx
			}
			wrapped = wr.TokenBuffer[0]
		}

		tag = misc.TOKEN_DATA
		if !nowrap {
			tag |= misc.TOKEN_WRAPPED
		}
		if !noenc {
			tag |= misc.TOKEN_ENCRYPTED
		}
		if !nomic {
			tag |= misc.TOKEN_SEND_MIC
		}
		if v1 {
			tag = 0
		}

		misc.SendToken(conn, tag, wrapped)
		tag, mictoken := misc.RecvToken(conn)
		if tag == 0 && len(mictoken) == 0 {
			if !quiet {
				fmt.Printf("Server closed connection unexpectedly.\n")
			}
			return
		}
		if nomic {
			if bytes.Equal(plain, mictoken) {
				if !quiet {
					fmt.Printf("Response differed.\n")
				}
				return
			}
			if !quiet {
				fmt.Printf("Response received.\n")
			}
		} else {
			vr, err := proxy.VerifyMic(pconn, pcc, ctx, plain, mictoken)
			if err != nil {
				fmt.Printf("Error verifying mic: %s\n", err)
				return
			}
			status = vr.Status
			major = status.MajorStatus
			if major != proxy.S_COMPLETE {
				displayStatus("verifying signature", status)
				return
			}
			pcc.ServerCtx = vr.Status.ServerCtx
			if vr.SecCtx != nil {
				ctx = *vr.SecCtx
				pctx = &ctx
			}
			if !quiet {
				fmt.Printf("Signature verified.\n")
			}
		}
	}
	if !v1 {
		misc.SendToken(conn, misc.TOKEN_NOOP, nil)
	}
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

func main() {
	port := flag.Int("port", 4444, "port")
	mechstr := flag.String("mech", "", "mechanism")
	spnego := flag.Bool("spnego", false, "use SPNEGO")
	iakerb := flag.Bool("iakerb", false, "use IAKERB")
	krb5 := flag.Bool("krb5", false, "use Kerberos 5")
	delegate := flag.Bool("d", false, "delegate")
	seq := flag.Bool("seq", false, "use sequence number checking")
	noreplay := flag.Bool("noreplay", false, "disable replay checking")
	nomutual := flag.Bool("nomutual", false, "perform one-way authentication")
	file := flag.Bool("f", false, "read message from file")
	v1 := flag.Bool("v1", false, "use version 1 protocol")
	quiet := flag.Bool("q", false, "quiet")
	ccount := flag.Int("ccount", 1, "connection count")
	mcount := flag.Int("mcount", 1, "message count")
	noauth := flag.Bool("na", false, "no authentication")
	nowrap := flag.Bool("nw", false, "no wrapping")
	noenc := flag.Bool("nx", false, "no encryption")
	nomic := flag.Bool("nm", false, "no MICs")
	var plain []byte
	var nmech *asn1.ObjectIdentifier
	var mech asn1.ObjectIdentifier
	var call proxy.CallCtx

	flag.Parse()
	sockaddr := flag.Arg(0)
	host := flag.Arg(1)
	service := flag.Arg(2)
	msg := flag.Arg(3)
	if flag.NArg() < 4 {
		fmt.Printf("Usage: proxy-client [options] socket host gss-service-name message-or-file\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *file {
		msgfile, err := os.Open(msg)
		if err != nil {
			fmt.Printf("Error opening \"%s\": %s", msg, err)
			return
		}
		fi, err := msgfile.Stat()
		if err != nil {
			fmt.Printf("Error statting \"%s\": %s", msg, err)
			return
		}
		plain = make([]byte, fi.Size())
		n, err := msgfile.Read(plain)
		if int64(n) != fi.Size() {
			fmt.Printf("Error reading \"%s\": %s", msg, err)
			return
		}
	} else {
		buffer := bytes.NewBufferString(msg)
		plain = buffer.Bytes()
	}
	if *spnego {
		/* If we're doing SPNEGO, then a passed-in mechanism OID is the one we want to negotiate, but we can't. */
		fmt.Printf("Warning: set_neg_mechs is not available.\n")
		tmpmech := parseOid("1.3.6.1.5.5.2")
		nmech = &tmpmech
		mech = tmpmech
	} else if *krb5 {
		tmpmech := parseOid("1.2.840.113554.1.2.2")
		nmech = &tmpmech
		mech = tmpmech
	} else if *iakerb {
		tmpmech := parseOid("1.3.6.1.5.2.5")
		nmech = &tmpmech
		mech = tmpmech
	} else if len(*mechstr) > 0 {
		tmpmech := parseOid(*mechstr)
		nmech = &tmpmech
		mech = tmpmech
	} else {
		tmpmech := parseOid("1.2.840.113554.1.2.2")
		nmech = &tmpmech
	}
	if *noauth {
		*nowrap = true
		*noenc = true
		*nomic = true
	}

	pconn, err := net.Dial("unix", sockaddr)
	if err != nil {
		fmt.Printf("Error connecting to gss-proxy at \"%s\": %s", sockaddr, err)
		return
	}

	ctr, err := proxy.GetCallContext(&pconn, call, nil)
	if err != nil {
		fmt.Printf("Error getting a calling context: %s", err)
		return
	}
	call.ServerCtx = ctr.ServerCtx

	for c := 0; c < *ccount; c++ {
		connectOnce(&pconn, call, host, *port, service, *mcount, *quiet, plain, *v1, nmech, mech, *delegate, *seq, *noreplay, *nomutual, *noauth, *nowrap, *noenc, *nomic)
	}
}
