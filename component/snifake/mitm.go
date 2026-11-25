// mitm.go implements the certificate-MITM path (route X): for a target domain
// that matches a sni-mimic rule, mihomo TERMINATES the app's TLS session using
// a leaf certificate dynamically signed by the in-memory root (so the app can
// validate it once the root is trusted, with NO ignore-certificate-errors),
// then RE-ORIGINATES its own TLS to the real IP with a benign alias SNI and a
// chrome fingerprint. The wire only ever shows the alias SNI.
package snifake

import (
	"bufio"
	"io"
	"net"
	"sync"
	"time"

	xutls "github.com/metacubex/utls"
)

var (
	signerOnce sync.Once
	signer     *Signer
	signerErr  error
)

// EnsureSigner lazily loads (or creates and persists) the root CA once per
// process, so the exported root certificate stays stable across restarts.
func EnsureSigner() (*Signer, error) {
	signerOnce.Do(func() {
		signer, signerErr = LoadOrCreate(Dir())
	})
	return signer, signerErr
}

// appSideConn is the net.Conn the MITM TLS server runs over: reads carry
// ciphertext coming from the app, writes carry ciphertext going back to the
// app. Both are backed by io.Pipes so the outer shuttle (mitmConn) can move
// raw bytes between the tunnel and appTLS without a real socket on the app side.
type appSideConn struct {
	r io.Reader // app -> appTLS (ciphertext)
	w io.Writer // appTLS -> app (ciphertext)
}

func (c *appSideConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *appSideConn) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *appSideConn) Close() error {
	// the pipe ends carry the close signal; a plain reader has none
	if cr, ok := c.r.(interface{ CloseWithError(error) error }); ok {
		_ = cr.CloseWithError(net.ErrClosed)
	}
	if cw, ok := c.w.(interface{ CloseWithError(error) error }); ok {
		_ = cw.CloseWithError(net.ErrClosed)
	}
	return nil
}
func (c *appSideConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *appSideConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *appSideConn) SetDeadline(time.Time) error      { return nil }
func (c *appSideConn) SetReadDeadline(time.Time) error  { return nil }
func (c *appSideConn) SetWriteDeadline(time.Time) error { return nil }

// mitmConn is the net.Conn handed back to the tunnel. It shuttles raw bytes
// between the app and an internal MITM bridge started lazily on first I/O.
type mitmConn struct {
	realConn net.Conn // already connected to the real IP
	domain   string   // real destination name
	plan     Plan     // SNI (or its absence) placed on the wire

	inW  *io.PipeWriter // shuttle.Write -> appTLS (ciphertext from app)
	outR *io.PipeReader // appTLS.Write -> shuttle.Read (ciphertext to app)

	startOnce sync.Once
	runErr    error
	runDone   chan struct{}
}

func newMITMConn(real net.Conn, domain string, plan Plan) *mitmConn {
	rIn, wIn := io.Pipe()   // app ciphertext feeds appTLS
	rOut, wOut := io.Pipe() // appTLS ciphertext reaches the app
	m := &mitmConn{
		realConn: real,
		domain:   domain,
		plan:     plan,
		inW:      wIn,
		outR:     rOut,
		runDone:  make(chan struct{}),
	}
	// keep rIn/wOut tied to the app side inside the bridge
	m.bridge(rIn, wOut)
	return m
}

// bridge starts the MITM goroutine and closes over the app-side pipe ends.
func (m *mitmConn) bridge(rIn *io.PipeReader, wOut *io.PipeWriter) {
	go func() {
		defer close(m.runDone)
		m.run(rIn, wOut)
	}()
}

func (m *mitmConn) run(rIn *io.PipeReader, wOut *io.PipeWriter) {
	// A rule says nothing about the protocol the application speaks. If this
	// connection is not a TLS handshake, terminating it would corrupt the
	// traffic, so shuttle the bytes through unchanged instead.
	peek := bufio.NewReader(rIn)
	if head, err := peek.Peek(1); err != nil || len(head) == 0 || head[0] != 0x16 {
		m.passthrough(peek, wOut)
		return
	}

	s, err := EnsureSigner()
	if err != nil {
		m.fail(err)
		return
	}
	cert, err := s.LeafFor(m.domain)
	if err != nil {
		m.fail(err)
		return
	}

	// app-facing server: leaf cert for the REAL domain chains to our root, so
	// a client that trusts the root validates without ignore-certificate-errors.
	serverCfg := &xutls.Config{
		Certificates: []xutls.Certificate{{
			Certificate: cert.ChainDER,
			PrivateKey:  cert.LeafKey,
		}},
		MinVersion: xutls.VersionTLS12,
	}

	// origin-facing client: the fake SNI (empty means the extension is left
	// off entirely, Cealing's null form), real IP, skip origin cert (we
	// re-present a freshly signed leaf to the app, so origin validation here
	// is intentionally relaxed — this is the MITM trust boundary).
	clientCfg := &xutls.Config{
		ServerName:         m.plan.SNI,
		InsecureSkipVerify: true,
	}

	appTLS := xutls.Server(&appSideConn{r: peek, w: wOut}, serverCfg)
	upTLS := xutls.UClient(m.realConn, clientCfg, xutls.HelloChrome_Auto)

	// The origin handshake uses the already-connected TCP and is independent of
	// the app; do it first, then complete the app handshake.
	if err := upTLS.Handshake(); err != nil {
		appTLS.Close()
		m.fail(err)
		return
	}
	if err := appTLS.Handshake(); err != nil {
		upTLS.Close()
		m.fail(err)
		return
	}

	go func() {
		_, _ = io.Copy(upTLS, appTLS) // app cleartext -> origin
		upTLS.Close()
	}()
	_, _ = io.Copy(appTLS, upTLS) // origin cleartext -> app
	appTLS.Close()
}

// passthrough relays the connection in both directions without touching it.
func (m *mitmConn) passthrough(app *bufio.Reader, toApp *io.PipeWriter) {
	go func() {
		_, _ = io.Copy(toApp, m.realConn)
		toApp.CloseWithError(net.ErrClosed)
	}()
	_, _ = io.Copy(m.realConn, app)
	m.realConn.Close()
}

func (m *mitmConn) fail(err error) {
	m.runErr = err
	if m.inW != nil {
		m.inW.CloseWithError(err)
	}
	if m.outR != nil {
		m.outR.CloseWithError(err)
	}
	m.realConn.Close()
}

func (m *mitmConn) Read(b []byte) (int, error)  { return m.outR.Read(b) }
func (m *mitmConn) Write(b []byte) (int, error) { return m.inW.Write(b) }

func (m *mitmConn) Close() error {
	if m.inW != nil {
		m.inW.CloseWithError(net.ErrClosed)
	}
	if m.outR != nil {
		m.outR.CloseWithError(net.ErrClosed)
	}
	return m.realConn.Close()
}

func (m *mitmConn) LocalAddr() net.Addr                { return m.realConn.LocalAddr() }
func (m *mitmConn) RemoteAddr() net.Addr               { return m.realConn.RemoteAddr() }
func (m *mitmConn) SetDeadline(t time.Time) error      { return m.realConn.SetDeadline(t) }
func (m *mitmConn) SetReadDeadline(t time.Time) error  { return m.realConn.SetReadDeadline(t) }
func (m *mitmConn) SetWriteDeadline(t time.Time) error { return m.realConn.SetWriteDeadline(t) }
