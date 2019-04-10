package mysocks5

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	socks5Version = uint8(5)
	noAuth        = uint8(0)
)

var key = []byte("dengzhicong12345")

// Config is used to setup and configure a Server
type Config struct {
	// BindIP is used for bind or udp associate
	BindIP net.IP
	Logger *log.Logger
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config *Config
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	server := &Server{
		config: conf,
	}
	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	fmt.Printf("listening to %v\n", addr)
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)
	s1, s2 := stateVector(key), stateVector(key)
	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}
	// Ensure we are compatible
	version = encrypt(version, s1)
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	if err := s.needNoAuth(bufConn, conn, s1, s2); err != nil {
		s.config.Logger.Printf("[ERR] socks: Invalid method region: %v", err)
		return err
	}
	request, err := NewRequest(bufConn, s1)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil, s1); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}
	// Process the client request
	if err := s.handleRequest(request, conn, s1, s2); err != nil && err != io.EOF {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}
	return nil
}

// 告诉客户端我们采用无认证的方式连接
func (s *Server) needNoAuth(r io.Reader, w io.Writer, s1, s2 []byte) error {
	header := []byte{0}
	if _, err := r.Read(header); err != nil {
		return err
	}
	header = encrypt(header, s1)
	numMethods := int(header[0])
	methods := make([]byte, numMethods)
	if _, err := io.ReadAtLeast(r, methods, numMethods); err != nil {
		return err
	}
	methods = encrypt(methods, s1)
	fmt.Println(methods)
	_, err := w.Write(encrypt([]byte{socks5Version, noAuth}, s2))
	return err
}

func stateVector(key []byte) []byte {
	s, t := make([]byte, 258), make([]byte, 256) //s最后两字节存加解密时的i,j值
	l := len(key)
	for i := 0; i < 256; i++ {
		s[i] = uint8(i)
		t[i] = key[i%l]
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]+t[i])) % 256
		s[i], s[j] = s[j], s[i]
	}
	return s
}

func encrypt(text []byte, s []byte) []byte {
	for l := 0; l < len(text); l++ {
		/*s[256] = uint8(int(s[256]+1) % 256)
		i := s[256]
		s[257] = uint8(int(s[257]+s[i]) % 256)
		j := s[257]
		s[i], s[j] = s[j], s[i]
		t := int(s[i]+s[j]) % 256
		k := s[t]
		text[l] ^= k*/
		text[l] = uint8(int(128+text[l]) % 256)
	}
	return text
}
