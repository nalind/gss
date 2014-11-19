package main

import "bytes"
import "flag"
import "fmt"
import "gss"
import "gss/misc"
import "net"
import "os"
import "strings"
import "encoding/asn1"

func connectOnce(host string, port int, service string, mcount int, quiet bool, user, pass string, plain []byte, v1, delegate, seq, noreplay, nomutual, noauth, nowrap, noenc, nomic bool) {
	const (
		TOKEN_NOOP    byte = (1 << 0)
		TOKEN_CONTEXT byte = (1 << 1)
		TOKEN_DATA    byte = (1 << 2)
		TOKEN_MIC     byte = (1 << 3)

		TOKEN_CONTEXT_NEXT byte = (1 << 4)
		TOKEN_WRAPPED      byte = (1 << 5)
		TOKEN_ENCRYPTED    byte = (1 << 6)
		TOKEN_SEND_MIC     byte = (1 << 7)
	)
	var ctx gss.ContextHandle
	var tag byte
	var itoken, otoken []byte
	var major, minor uint32
	var sname string
	var mech asn1.ObjectIdentifier
	var flags gss.Flags

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Printf("Error connecting: %s\n", err)
		os.Exit(2)
	}
	defer conn.Close()

	if strings.Contains(service, "@") {
		sname = service
	} else {
		sname = service + "@" + host
	}
	major, minor, name := gss.ImportName(sname, gss.C_NT_HOSTBASED_SERVICE)
	if major != 0 {
		misc.DisplayError(major, minor, nil)
		return
	}
	defer gss.ReleaseName(name)

	if !v1 {
		misc.SendToken(conn, TOKEN_NOOP|TOKEN_CONTEXT_NEXT, nil)
	}

	if noauth {
		misc.SendToken(conn, TOKEN_NOOP, nil)
	} else {
		flags = gss.Flags{Deleg: delegate, Sequence: seq, Replay: !noreplay, Conf: !noenc, Integ: !nomic, Mutual: !nomutual}
		for true {
			major, minor, mech, otoken, flags, _, _, _ = gss.InitSecContext(nil, &ctx, name, nil, flags, 0, nil, itoken)
			if major != gss.S_COMPLETE && major != gss.S_CONTINUE_NEEDED {
				misc.DisplayError(major, minor, &mech)
				return
			}
			if len(otoken) > 0 {
				if !quiet {
					fmt.Printf("Sending init_sec_context token (%d bytes)...", len(otoken))
				}
				if v1 {
					tag = TOKEN_CONTEXT
				} else {
					tag = 0
				}
				misc.SendToken(conn, tag, otoken)
			}
			if major == gss.S_CONTINUE_NEEDED {
				if !quiet {
					fmt.Printf("continue needed...")
				}
				tag, itoken = misc.RecvToken(conn)
				if !quiet {
					fmt.Printf("\nReceived new input token (%d bytes).\n", len(itoken))
				}
			} else {
				if !quiet {
					fmt.Printf("Done authenticating.\n")
				}
				defer gss.DeleteSecContext(ctx)
				break
			}
		}
		if major != gss.S_COMPLETE {
			fmt.Printf("Error authenticating to server: %x/%x.\n", major, minor)
			return
		}
		misc.DisplayFlags(flags)
	}

	for i := 0; i < mcount; i++ {
		var wrapped []byte
		var major, minor uint32
		var encrypted bool

		if nowrap {
			wrapped = plain
		} else {
			major, minor, encrypted, wrapped = gss.Wrap(ctx, !noenc, gss.C_QOP_DEFAULT, plain)
			if major != gss.S_COMPLETE {
				misc.DisplayError(major, minor, &mech)
				return
			}
		}
		if !noenc && !encrypted {
			fmt.Printf("Warning!  Message not encrypted.\n")
		}

		tag = TOKEN_DATA
		if !nowrap {
			tag |= TOKEN_WRAPPED
		}
		if !noenc {
			tag |= TOKEN_ENCRYPTED
		}
		if !nomic {
			tag |= TOKEN_SEND_MIC
		}
		if v1 {
			tag = 0
		}

		misc.SendToken(conn, tag, wrapped)
		_, mictoken := misc.RecvToken(conn)
		if nomic {
			if !quiet {
				fmt.Printf("Response received.\n")
			}
		} else {
			major, minor, _ = gss.VerifyMIC(ctx, plain, mictoken)
			if major != gss.S_COMPLETE {
				misc.DisplayError(major, minor, &mech)
				return
			}
			if !quiet {
				fmt.Printf("Signature verified.\n")
			}
		}
	}
	if !v1 {
		misc.SendToken(conn, TOKEN_NOOP, nil)
	}
}

func main() {
	port := flag.Int("port", 4444, "port")
	/*
		mech := flag.String("mech", "", "mechanism")
		spnego := flag.Bool("spnego", false, "use SPNEGO")
	*/
	delegate := flag.Bool("d", false, "delegate")
	seq := flag.Bool("seq", false, "use sequence number checking")
	noreplay := flag.Bool("noreplay", false, "disable replay checking")
	nomutual := flag.Bool("nomutual", false, "perform one-way authentication")
	user := flag.String("user", "", "user name")
	pass := flag.String("pass", "", "password")
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

	flag.Parse()
	host := flag.Arg(0)
	service := flag.Arg(1)
	msg := flag.Arg(2)
	if flag.NArg() < 3 {
		flag.Usage()
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

	for c := 0; c < *ccount; c++ {
		connectOnce(host, *port, service, *mcount, *quiet, *user, *pass, plain, *v1, *delegate, *seq, *noreplay, *nomutual, *noauth, *nowrap, *noenc, *nomic)
	}
}
