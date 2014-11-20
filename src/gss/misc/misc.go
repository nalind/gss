package misc

import "fmt"
import "gss"
import "net"
import "os"
import "encoding/binary"
import "encoding/asn1"

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

func DisplayError(when string, major, minor uint32, mech *asn1.ObjectIdentifier) {
	fmt.Print(gss.DisplayStatus(major, gss.C_GSS_CODE, nil))
	fmt.Printf(" ")
	if len(when) > 0 {
		fmt.Printf("while %s", when)
	}
	fmt.Printf("\n")
	if mech != nil {
		fmt.Print(gss.DisplayStatus(major, gss.C_MECH_CODE, *mech))
		fmt.Printf("\n")
	}
}

func DisplayFlags(flags gss.Flags) {
	if flags.Deleg {
		fmt.Printf("context flag: GSS_C_DELEG_FLAG\n")
	}
	if flags.Mutual {
		fmt.Printf("context flag: GSS_C_MUTUAL_FLAG\n")
	}
	if flags.Replay {
		fmt.Printf("context flag: GSS_C_REPLAY_FLAG\n")
	}
	if flags.Sequence {
		fmt.Printf("context flag: GSS_C_SEQUENCE_FLAG\n")
	}
	if flags.Conf {
		fmt.Printf("context flag: GSS_C_CONF_FLAG\n")
	}
	if flags.Integ {
		fmt.Printf("context flag: GSS_C_INTEG_FLAG\n")
	}
}

func SendToken(conn net.Conn, tag byte, token []byte) {
	tlen := uint32(len(token))

	if tag != 0 {
		binary.Write(conn, binary.BigEndian, tag)
	}
	binary.Write(conn, binary.BigEndian, tlen)
	conn.Write(token)
}

func RecvToken(conn net.Conn) (tag byte, token []byte) {
	var tlen uint32
	tmp := make([]byte, 1)

	_, err := conn.Read(tmp)
	if err != nil {
		fmt.Printf("Error reading flag from server: %s.\n", err)
		os.Exit(2)
	}
	tag = tmp[0]
	if tag != 0 {
		err = binary.Read(conn, binary.BigEndian, &tlen)
		if err != nil {
			fmt.Printf("Error reading tags from server: %s.\n", err)
			os.Exit(2)
		}
	} else {
		tags := make([]byte, 3)
		_, err := conn.Read(tags)
		if err != nil {
			fmt.Printf("Error reading length from server: %s.\n", err)
			os.Exit(2)
		}
		tlen = uint32((tag << 24) | (tags[0] << 16) | (tags[1] << 8) | tags[2])
	}
	token = make([]byte, tlen)
	_, err = conn.Read(token)
	if err != nil {
		fmt.Printf("Error reading from server: %s.\n", err)
		os.Exit(2)
	}
	return
}
