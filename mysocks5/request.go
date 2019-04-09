package mysocks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(request *Request) *AddrSpec
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, Ipv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a *AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AddrSpec of the network that sent the reques
	RemoteAddr *AddrSpec
	// AddrSpect of the desired destination
	DestAddr *AddrSpec
	// AddrSpec of the actual destination(might be affected by rewrite)
	realDestAddr *AddrSpec
	bufConn      io.Reader
}

// NewRequest creates a new Request from the tcp connection
func NewRequest(bufConn io.Reader, s1 []byte) (*Request, error) {
	// Read the command and version  byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 3); err != nil {
		fmt.Println("hhh")
		return nil, fmt.Errorf("Failed to get version and command: %v", err)
	}
	encrypt(header, s1)
	// Ensure we are compatible
	if header[0] != socks5Version {

		return nil, fmt.Errorf("Unsupported command version: %v", header[0])
	}

	//Read in the destination address
	dest, err := readAddrSpec(bufConn, s1)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		bufConn:  bufConn,
	}
	return request, nil
}

// handleRequest is used for request processing
func (s *Server) handleRequest(req *Request, conn net.Conn, s1, s2 []byte) error {
	dest := req.DestAddr
	if dest.FQDN != "" {
		addr, err := net.ResolveIPAddr("ip", dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil, s2); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		dest.IP = addr.IP
	}
	// Apply any address rewrites
	req.realDestAddr = req.DestAddr

	//Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s.handleConnect(conn, req, s1, s2)
	default:
		if err := sendReply(conn, commandNotSupported, nil, s2); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}

}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(conn net.Conn, req *Request, s1 []byte, s2 []byte) error {
	// Attemp to connect
	target, err := net.Dial("tcp", req.realDestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network isunreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil, s2); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind, s2); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	// Start proxying
	errCh := make(chan error, 2)
	go forward(target, req.bufConn, errCh, s1)
	go forward(conn, target, errCh, s2)

	//Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			return e
		}
	}
	return nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader, s1 []byte) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}
	encrypt(addrType, s1)
	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		encrypt(addr, s1)
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		encrypt(addr, s1)
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		encrypt(addrType, s1)
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		encrypt(fqdn, s1)
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	encrypt(port, s1)
	d.Port = (int(port[0]) << 8) | int(port[1])
	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec, s2 []byte) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0
	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)
	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)
	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}
	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)
	encrypt(msg, s2)
	// Send the message
	_, err := w.Write(msg)
	return err
}

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		tcpConn.CloseWrite()
	}
	errCh <- err
}

func forward(dst io.Writer, src io.Reader, errCh chan error, s []byte) {
	bufSize := 4096
	p := make([]byte, bufSize)
	defer func() {
		if tcpConn, ok := dst.(closeWriter); ok {
			tcpConn.CloseWrite()
		}
	}()
	for {
		n, err := src.Read(p)
		if err != nil {
			errCh <- err
			return
		}
		t1 := time.Now()
		text := encrypt(p[:n], s)
		t := time.Now().Sub(t1)
		fmt.Printf("elapsed: %d us\n", t.Nanoseconds()/1000)
		_, err = dst.Write(text)
		if err != nil {
			errCh <- err
			return
		}
	}
}
