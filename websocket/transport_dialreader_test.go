package websocket

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/ORBTR/aether"
)

// heldUpgradeWriter keeps the server's 101 response in held instead of
// writing it, so the handler can send the response and its first frame in
// one write and the dialler reads both in the same read.
type heldUpgradeWriter struct {
	http.ResponseWriter
	held *bytes.Buffer
}

func (h *heldUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(h.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReadWriter(rw.Reader, bufio.NewWriter(h.held)), nil
}

// A server that writes its first frame in the same segment as its 101 is read
// by the dialler: the frame reaches the connection's first Receive.
func TestDial_ReadsTheFrameTheServerSendsWithItsUpgradeResponse(t *testing.T) {
	_, srvPriv, srvID := aep26Identity(t)
	_, cliPriv, cliID := aep26Identity(t)
	server := aep26Transport(t, srvID, srvPriv, "")
	want := []byte("sent with the upgrade response")

	done := make(chan struct{})
	defer close(done)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var held bytes.Buffer
		conn, _, _, err := ws.HTTPUpgrader{Header: server.AcceptHeaders(r)}.Upgrade(r, &heldUpgradeWriter{ResponseWriter: w, held: &held})
		if err != nil {
			t.Errorf("upgrade: %v", err)
			return
		}
		defer conn.Close()
		if err := ws.WriteFrame(&held, ws.NewBinaryFrame(want)); err != nil {
			t.Errorf("frame: %v", err)
			return
		}
		if _, err := conn.Write(held.Bytes()); err != nil {
			t.Errorf("write: %v", err)
			return
		}
		<-done
	}))
	defer srv.Close()

	client := aep26Transport(t, cliID, cliPriv, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, aether.Target{NodeID: srvID, Address: "ws://" + srv.Listener.Addr().String() + "/"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	got, err := conn.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v (the frame written with the 101 was not read)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("receive = %q, want %q", got, want)
	}
}
