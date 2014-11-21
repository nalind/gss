package main

import "encoding/asn1"
import "flag"
import "fmt"
import "gss"
import "gss/misc"
import "net"
import "os"
import "strconv"

func serve(conn net.Conn, cred gss.CredHandle, export, verbose bool) {
	var ctx gss.ContextHandle
	var dcred gss.CredHandle
	var cname gss.InternalName
	var flags gss.Flags
	var mech asn1.ObjectIdentifier
	var client string
	var major, minor uint32
	var conf bool

	defer conn.Close()

	tag, token := misc.RecvToken(conn)
	if tag == 0 && len(token) == 0 {
		fmt.Printf("EOF from client\n", tag)
		return
	}
	if (tag & misc.TOKEN_NOOP) == 0 {
		fmt.Printf("Expected NOOP token, got %d token instead.\n", tag)
		return
	}
	if (tag & misc.TOKEN_CONTEXT_NEXT) != 0 {
		for {
			/* Expect a context establishment token. */
			tag, token := misc.RecvToken(conn)
			if tag == 0 && len(token) == 0 {
				break
			}
			if verbose {
				fmt.Printf("Received token (%d bytes):\n", len(token))
			}
			if tag&misc.TOKEN_CONTEXT == 0 {
				fmt.Printf("Expected context establishment token, got %d token instead.\n", tag)
				break
			}
			major, minor, cname, mech, flags, _, _, _, dcred, token = gss.AcceptSecContext(cred, &ctx, nil, token)
			if len(token) > 0 {
				/* If we got a new token, send it to the client. */
				if verbose {
					fmt.Printf("Sending accept_sec_context token (%d bytes):\n", len(token))
				}
				misc.SendToken(conn, misc.TOKEN_CONTEXT, token)
			}
			if cname != nil {
				major, minor, client, _ = gss.DisplayName(cname)
				if major != gss.S_COMPLETE {
					misc.DisplayError("displaying name", major, minor, &mech)
				}
				defer gss.ReleaseName(cname)
				cname = nil
			}
			if dcred != nil {
				defer gss.ReleaseCred(dcred)
				dcred = nil
			}
			if major != gss.S_COMPLETE && major != gss.S_CONTINUE_NEEDED {
				/* There was some kind of error. */
				misc.DisplayError("accepting context", major, minor, &mech)
			}
			if major == gss.S_COMPLETE {
				/* Okay, success. */
				defer gss.DeleteSecContext(ctx)
				break
			}
			/* Wait for another context establishment token. */
			if verbose {
				fmt.Printf("continue needed...\n")
			}
		}
		/* Dig up information about the connection. */
		misc.DisplayFlags(flags)
		major, minor, oid := gss.OidToStr(mech)
		if major != gss.S_COMPLETE {
			misc.DisplayError("converting oid to string", major, minor, &mech)
		}
		if verbose {
			fmt.Printf("Accepted connection using mechanism OID %s.\n", oid)
		}
	} else {
		if verbose {
			fmt.Printf("Accepted unauthenticated connection.\n")
		}
	}
	/* Start processing message tokens from the client. */
	if ctx != nil {
		fmt.Printf("Accepted connection: \"%s\"\n", client)
	} else {
		fmt.Printf("Accepted unauthenticated connection.\n")
	}
	for {
		/* Read a request. */
		tag, token := misc.RecvToken(conn)
		if tag == 0 && len(token) == 0 {
			if verbose {
				fmt.Printf("EOF from client.\n")
			}
			return
		}
		/* Client indicates EOF with another NOOP token. */
		if tag&misc.TOKEN_NOOP != 0 {
			if verbose {
				fmt.Printf("NOOP token.\n")
			}
			break
		}
		/* Expect data tokens. */
		if tag&misc.TOKEN_DATA == 0 {
			fmt.Printf("Expected data token, got %d token instead.\n", tag)
			break
		}
		if verbose {
			fmt.Printf("Message token (flags=%d).\n", tag)
		}
		/* No context handle means no encryption or signing. */
		if ctx == nil && (tag&(misc.TOKEN_WRAPPED|misc.TOKEN_ENCRYPTED|misc.TOKEN_SEND_MIC)) != 0 {
			if verbose {
				fmt.Printf("Unauthenticated client requested authenticated services!\n")
			}
			break
		}
		/* If it's wrapped at all, unwrap it. */
		if tag&misc.TOKEN_WRAPPED != 0 {
			major, minor, conf, _, token = gss.Unwrap(ctx, token)
			if major != gss.S_COMPLETE {
				misc.DisplayError("unwrapping message", major, minor, &mech)
				break
			}
			/* If we were told it was encrypted, and it wasn't, warn. */
			if !conf && misc.TOKEN_ENCRYPTED != 0 {
				fmt.Printf("Warning!  Message not encrypted.\n")
			}
		}
		/* Log it. */
		if verbose {
			fmt.Printf("Received message:\n")
		}
		/* Reply. */
		if tag&misc.TOKEN_SEND_MIC != 0 {
			/* Send back a signature over the payload data. */
			major, minor, token := gss.GetMIC(ctx, gss.C_QOP_DEFAULT, token)
			if major != gss.S_COMPLETE {
				misc.DisplayError("signing message", major, minor, &mech)
				break
			}
			misc.SendToken(conn, misc.TOKEN_MIC, token)
		} else {
			/* Send back a minimal acknowledgement. */
			misc.SendToken(conn, misc.TOKEN_NOOP, nil)
		}
	}
}

func main() {
	port := flag.Int("port", 4444, "port")
	verbose := flag.Bool("verbose", false, "verbose")
	once := flag.Bool("once", false, "single-connection mode")
	export := flag.Bool("export", false, "export the context")
	keytab := flag.String("keytab", "", "keytab location")

	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Printf("Usage: gss-server [options] gss-service-name\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	service := flag.Arg(0)

	/* Set up the listener socket. */
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(*port))
	if err != nil {
		fmt.Printf("Error listening for client connection: %s\n", err)
		return
	}
	defer listener.Close()

	/* Set up the server's name. */
	major, minor, name := gss.ImportName(service, gss.C_NT_HOSTBASED_SERVICE)
	if major != gss.S_COMPLETE {
		misc.DisplayError("importing name", major, minor, nil)
		return
	}
	defer gss.ReleaseName(name)

	/* If we're told to use a particular keytab, do so. */
	if len(*keytab) > 0 {
		minor := gss.Krb5RegisterAcceptorIdentity(*keytab)
		if minor != 0 {
			misc.DisplayError("registering acceptor identity", 0, minor, nil)
		}
	}

	/* Make sure we have acceptor creds. */
	major, minor, cred, _, _ := gss.AcquireCred(name, gss.C_INDEFINITE, nil, gss.C_ACCEPT)
	if major != gss.S_COMPLETE {
		misc.DisplayError("acquiring credentials", major, minor, nil)
		return
	}
	defer gss.ReleaseCred(cred)

	if *once {
		/* Service exactly one client. */
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting client connection: %s\n", err)
			return
		}
		serve(conn, cred, *export, *verbose)
	} else {
		/* Just keep serving clients. */
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("Error accepting client connection: %s\n", err)
				continue
			}
			go serve(conn, cred, *export, *verbose)
		}
	}
	return
}
