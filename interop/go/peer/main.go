// Command peer drives go-iec61850's security layers from the command line,
// for rs-iec61850's interop suite (tests/interop_go.rs):
//
//	peer MODE ADDR PORT KEYID KEYHEX SECALGO SIGALGO COUNT
//	    R-GOOSE and R-SV, with the arguments and output of libiec61850's
//	    interop/c/rsession_peer.c: MODE is goose-pub, goose-sub, sv-pub or
//	    sv-sub, so the same tests run against both.
//	peer gdoi-server ADDR psk SECRET | cert CERT KEY ROOT
//	    a GDOI key server for group 1.2.840.10070.61850.1 with one
//	    AES-GCM-128 TEK; prints "listening ADDR", "tek SPI KEYHEX" and
//	    "register PEER" per registration, until stdin closes.
//	peer gdoi-member SERVER psk SECRET | cert CERT KEY ROOT
//	    registers once and prints "server PEER" and "tek SPI ENC AUTH KEYHEX".
//	peer tls-server ADDR CERT KEY ROOT
//	    an MMS server under the IEC 62351-3 profile serving simpleIO;
//	    prints "listening ADDR", until stdin closes.
//	peer tls-client ADDR CERT KEY ROOT NAME
//	    associates under the profile, reads GGIO1.AnIn1.mag.f, prints
//	    "read VALUE".
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/gdoi"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/rsession"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
	"github.com/dscsystems/go-iec61850/sv"
)

var groupOID = asn1.ObjectIdentifier{1, 2, 840, 10070, 61850, 1}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: peer MODE ...")
	}
	switch mode := os.Args[1]; mode {
	case "goose-pub", "goose-sub", "sv-pub", "sv-sub":
		rsessionPeer(mode, os.Args[2:])
	case "gdoi-server":
		gdoiServer(os.Args[2:])
	case "gdoi-member":
		gdoiMember(os.Args[2:])
	case "tls-server":
		tlsServer(os.Args[2:])
	case "tls-client":
		tlsClient(os.Args[2:])
	default:
		fail("unknown mode %s", mode)
	}
}

func rsessionPeer(mode string, args []string) {
	if len(args) != 7 {
		fail("usage: peer %s ADDR PORT KEYID KEYHEX SECALGO SIGALGO COUNT", mode)
	}
	addr := net.JoinHostPort(args[0], args[1])
	keyID, _ := strconv.Atoi(args[2])
	sec, _ := strconv.Atoi(args[4])
	sig, _ := strconv.Atoi(args[5])
	count, _ := strconv.Atoi(args[6])
	var cfg rsession.Config
	if keyID == 0 {
		cfg.AllowUnsecured = true
	} else {
		material, err := hex.DecodeString(args[3])
		if err != nil {
			fail("bad key: %v", err)
		}
		ks, err := rsession.NewKeyStore(rsession.Key{ID: uint32(keyID), Material: material,
			Sec: rsession.SecAlgorithm(sec), Sig: rsession.SigAlgorithm(sig)})
		if err != nil {
			fail("key: %v", err)
		}
		cfg.Keys = ks
	}
	pub := mode == "goose-pub" || mode == "sv-pub"
	if pub {
		cfg.Remote = addr
	} else {
		cfg.Listen = addr
	}
	s, err := rsession.Open(cfg)
	if err != nil {
		fail("open: %v", err)
	}
	defer s.Close()

	switch mode {
	case "goose-pub":
		for i := 0; i < count; i++ {
			// A fresh publisher per message: each one is a state change, as
			// libiec61850's peer sends them.
			p, err := goose.NewPublisher(s, goose.PublisherConfig{AppID: 0x3001, GoCbRef: "GOISIM/LLN0$GO$gcb1",
				DatSet: "GOISIM/LLN0$DS1", GoID: "GOISIM", ConfRev: 1, Retrans: []time.Duration{time.Hour}})
			if err != nil {
				fail("publisher: %v", err)
			}
			if err := p.Publish([]*mms.Value{mms.NewInt32(1234), mms.NewBool(true), mms.NewVisibleString("r-goose")}); err != nil {
				fail("publish: %v", err)
			}
			p.Close()
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Printf("sent %d\n", count)
	case "sv-pub":
		sample := make([]byte, 8)
		binary.BigEndian.PutUint32(sample, math.Float32bits(1.5))
		binary.BigEndian.PutUint32(sample[4:], math.Float32bits(-2.25))
		for i := 0; i < count; i++ {
			pdu := &sv.PDU{AppID: 0x4001, ASDUs: []*sv.ASDU{{SvID: "RSV1", SmpCnt: uint16(i), ConfRev: 1, Sample: sample}}}
			if err := s.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeSV, Payload: pdu.Marshal()}); err != nil {
				fail("send: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		fmt.Printf("sent %d\n", count)
	case "goose-sub", "sv-sub":
		got := make(chan struct{}, 64)
		var stop func()
		if mode == "goose-sub" {
			stop, err = goose.NewSubscriber(s).Subscribe(goose.Filter{GoCbRef: "GOISIM/LLN0$GO$gcb1"}, func(m *goose.Message) {
				data := ""
				for i, v := range m.Values {
					if i > 0 {
						data += ","
					}
					if v.Type() == mms.TypeVisibleString {
						data += v.Text()
					} else {
						data += v.String()
					}
				}
				fmt.Printf("GOOSE st=%d sq=%d valid=1 data={%s}\n", m.StNum, m.SqNum, data)
				got <- struct{}{}
			})
		} else {
			stop, err = sv.NewSubscriber(s).Subscribe(sv.Filter{}, func(a *sv.ASDU) {
				var v0, v1 float32
				if len(a.Sample) >= 8 {
					v0 = math.Float32frombits(binary.BigEndian.Uint32(a.Sample))
					v1 = math.Float32frombits(binary.BigEndian.Uint32(a.Sample[4:]))
				}
				fmt.Printf("SV svID=%s smpCnt=%d v0=%g v1=%g\n", a.SvID, a.SmpCnt, v0, v1)
				got <- struct{}{}
			})
		}
		if err != nil {
			fail("subscribe: %v", err)
		}
		defer stop()
		fmt.Println("listening")
		received := 0
		deadline := time.After(5 * time.Second)
	wait:
		for received < count {
			select {
			case <-got:
				received++
			case <-deadline:
				break wait
			}
		}
		fmt.Printf("received %d\n", received)
		if received < count {
			os.Exit(1)
		}
	}
}

// credentials reads "psk SECRET" or "cert CERT KEY ROOT" (PEM files).
func credentials(args []string) (gdoi.Credentials, []string) {
	if len(args) >= 2 && args[0] == "psk" {
		return gdoi.Credentials{PSK: []byte(args[1])}, args[2:]
	}
	if len(args) >= 4 && args[0] == "cert" {
		cert, key, roots := loadPKI(args[1], args[2], args[3])
		return gdoi.Credentials{Certificate: []*x509.Certificate{cert}, Key: key, Roots: roots}, args[4:]
	}
	fail("credentials: psk SECRET | cert CERT KEY ROOT")
	return gdoi.Credentials{}, nil
}

func pemDER(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail("%v", err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		fail("%s: no PEM block", path)
	}
	return b.Bytes
}

func loadPKI(certPath, keyPath, rootPath string) (*x509.Certificate, crypto.Signer, *x509.CertPool) {
	cert, err := x509.ParseCertificate(pemDER(certPath))
	if err != nil {
		fail("%s: %v", certPath, err)
	}
	k, err := x509.ParsePKCS8PrivateKey(pemDER(keyPath))
	if err != nil {
		fail("%s: %v", keyPath, err)
	}
	root, err := x509.ParseCertificate(pemDER(rootPath))
	if err != nil {
		fail("%s: %v", rootPath, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return cert, k.(crypto.Signer), pool
}

// untilStdinCloses blocks until the test that started this peer goes.
func untilStdinCloses() { io.Copy(io.Discard, os.Stdin) }

func gdoiServer(args []string) {
	if len(args) < 1 {
		fail("usage: peer gdoi-server ADDR CREDENTIALS")
	}
	addr := args[0]
	cred, _ := credentials(args[1:])
	cfg := gdoi.ServerConfig{
		Authorize: func(gdoi.Peer, gdoi.GroupID) bool { return true },
		OnRegister: func(p gdoi.Peer, g gdoi.GroupID, teks []gdoi.TEK) {
			fmt.Printf("register %s\n", p)
		},
		OnReject: func(a net.Addr, err error) { fmt.Printf("reject %v\n", err) },
	}
	if len(cred.PSK) > 0 {
		psk := cred.PSK
		cfg.PSK = func(net.Addr) []byte { return psk }
	} else {
		cfg.Credentials = cred
	}
	ks, err := gdoi.NewServer(cfg)
	if err != nil {
		fail("server: %v", err)
	}
	g := &gdoi.Group{}
	tek, err := gdoi.NewTEK(groupOID, nil, gdoi.AuthNone, gdoi.EncAESGCM128, time.Hour)
	if err != nil {
		fail("tek: %v", err)
	}
	g.Add(tek)
	ks.AddGroup(gdoi.GroupID{OID: groupOID}, g)
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		fail("listen: %v", err)
	}
	go ks.Serve(c)
	fmt.Printf("tek %d %s\n", tek.SPI, hex.EncodeToString(tek.AlgorithmKey))
	fmt.Printf("listening %s\n", c.LocalAddr())
	untilStdinCloses()
	ks.Close()
}

func gdoiMember(args []string) {
	if len(args) < 1 {
		fail("usage: peer gdoi-member SERVER CREDENTIALS")
	}
	cred, _ := credentials(args[1:])
	cfg := gdoi.MemberConfig{Server: args[0], Credentials: cred, Retransmit: 500 * time.Millisecond}
	if len(cred.PSK) == 0 {
		cfg.AuthorizeServer = func(gdoi.Peer) error { return nil }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reg, err := gdoi.Register(ctx, cfg, gdoi.GroupID{OID: groupOID})
	if err != nil {
		fail("register: %v", err)
	}
	fmt.Printf("server %s\n", reg.Server)
	for _, t := range reg.TEKs {
		fmt.Printf("tek %d %d %d %s\n", t.SPI, t.Enc, t.Auth, hex.EncodeToString(t.AlgorithmKey))
	}
}

func tlsServer(args []string) {
	if len(args) != 4 {
		fail("usage: peer tls-server ADDR CERT KEY ROOT")
	}
	pair, err := tls.LoadX509KeyPair(args[1], args[2])
	if err != nil {
		fail("%v", err)
	}
	_, _, roots := loadPKI(args[1], args[2], args[3])
	cfg, err := iec62351.ServerConfig(iec62351.Options{Certificates: []tls.Certificate{pair}, Roots: roots,
		OnEvent: func(e iec62351.Event) { fmt.Printf("event %v\n", e.Err) }})
	if err != nil {
		fail("%v", err)
	}
	m, err := scl.LoadModel(os.Getenv("SIMPLEIO_CID"))
	if err != nil {
		fail("model: %v", err)
	}
	ln, err := net.Listen("tcp", args[0])
	if err != nil {
		fail("listen: %v", err)
	}
	srv := server.New(m, server.WithTLS(cfg))
	go srv.Serve(tls.NewListener(ln, cfg))
	fmt.Printf("listening %s\n", ln.Addr())
	untilStdinCloses()
	srv.Close()
}

func tlsClient(args []string) {
	if len(args) != 5 {
		fail("usage: peer tls-client ADDR CERT KEY ROOT NAME")
	}
	pair, err := tls.LoadX509KeyPair(args[1], args[2])
	if err != nil {
		fail("%v", err)
	}
	_, _, roots := loadPKI(args[1], args[2], args[3])
	cfg, err := iec62351.ClientConfig(iec62351.Options{Certificates: []tls.Certificate{pair}, Roots: roots, ServerName: args[4]})
	if err != nil {
		fail("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, args[0], client.WithTLS(cfg), client.WithTimeout(5*time.Second))
	if err != nil {
		fail("associate: %v", err)
	}
	defer c.Close()
	v, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.AnIn1.mag.f", model.MX)
	if err != nil {
		fail("read: %v", err)
	}
	fmt.Printf("read %v\n", v)
}
