package tools

import (
	"errors"
	"openspalib-poc"
	"strings"
)

// Returns the byte value of the protocol according to:
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml.
// If unsupported protocol, we will return an error.
func ConvertProtoStrToByte(proto string) (byte, error) {

	protocol := strings.ToUpper(proto)

	switch protocol {
	case "ICMP":
		return openspalib_poc.Protocol_ICMP, nil
	case "TCP":
		return openspalib_poc.Protocol_TCP, nil
	case "UDP":
		return openspalib_poc.Protocol_UDP, nil
	case "IPV4":
		return openspalib_poc.Protocol_IPV4, nil
	default:
		return 0x0, errors.New("unsupported protocol")
	}

}

// The opposite of ConvertProtoStrToByte - converts a byte to
// a string. If there is no mapping we will return an empty string.
func ConvertProtoByteToStr(b byte) string {
	switch b {
	case openspalib_poc.Protocol_ICMP:
		return "ICMP"
	case openspalib_poc.Protocol_TCP:
		return "TCP"
	case openspalib_poc.Protocol_UDP:
		return "UDP"
	case openspalib_poc.Protocol_IPV4:
		return "IPV4"
	default:
		return ""
	}
}

// Converts a signature method constant to a string.
func ConvertSignatureMethodByteToStr(b byte) string {
	switch b {
	case openspalib_poc.SignatureMethod_RSA_SHA256:
		return "RSA_SHA256"
	default:
		return ""
	}
}
