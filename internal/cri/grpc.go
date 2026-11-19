package cri

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

// A gRPC client for exactly one thing: unary calls to a CRI socket.
//
// gRPC is HTTP/2 plus a five-byte length prefix and two trailers, and that is
// all of it that a unary call needs. Writing those forty lines here instead of
// importing google.golang.org/grpc keeps 2.9 MB out of a binary whose size is
// published on a landing page, and keeps the dependency count of the agent
// where it is: x/net/http2 and the protobuf wire package are already in the
// module graph via client-go, so this adds no module at all.
//
// What it deliberately does not implement: streaming, compression,
// retries, load balancing, name resolution, interceptors. A CRI socket is one
// process on the same machine reached over a unix socket. None of that applies.

const (
	// maxResponse caps what a runtime can make the agent hold in memory.
	//
	// ContainerStatus with verbose=true returns the whole OCI runtime spec as
	// JSON — measured at 37 KB for one ordinary container on k3s — so the cap has
	// to be generous, but it must exist: without it a wedged or hostile runtime
	// decides the agent's memory usage.
	maxResponse = 16 << 20

	// callTimeout bounds a single RPC. The agent's inventory runs on a schedule
	// and must never be the reason a heartbeat is late, so a runtime that stops
	// answering costs us this once per call and nothing more.
	callTimeout = 5 * time.Second
)

// conn is a reusable HTTP/2 connection to a CRI socket.
type conn struct {
	http      *http.Client
	transport *http2.Transport
	endpoint  string
}

func dial(socket string) *conn {
	transport := &http2.Transport{
		// Prior-knowledge HTTP/2 over cleartext: there is no TLS on a unix
		// socket, and no ALPN to negotiate with.
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}

	return &conn{
		http:      &http.Client{Transport: transport},
		transport: transport,
		endpoint:  socket,
	}
}

// close releases the connection to the socket.
//
// Required, not tidiness: an HTTP/2 connection stays in the transport's pool
// with a read goroutine holding it open, so it is not collected when the
// transport goes out of scope. One leaked unix socket and goroutine per
// inventory run, on a process that runs for months, is a leak the agent would
// carry for its whole uptime.
func (c *conn) close() {
	c.transport.CloseIdleConnections()
}

// call makes one unary gRPC call and returns the response message bytes.
func (c *conn) call(ctx context.Context, method string, request []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	// A gRPC message on the wire is a one-byte compression flag, a big-endian
	// uint32 length, then the protobuf.
	frame := make([]byte, 5+len(request))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(request)))
	copy(frame[5:], request)

	// The authority is ignored by the dialer above, which always goes to the
	// socket. It has to be a syntactically valid URL all the same.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://cri"+method, bytes.NewReader(frame))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/grpc")
	// Required by the gRPC spec, and grpc-go's server rejects a request without
	// it rather than guessing.
	req.Header.Set("TE", "trailers")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cri %s: %w", method, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, fmt.Errorf("cri %s: read: %w", method, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cri %s: http %d", method, resp.StatusCode)
	}

	// grpc-status arrives in the trailers on a normal response and in the
	// headers when the server fails before sending a body. Both have to be
	// checked, or a refused call reads as an empty container list — which is the
	// exact failure this package must never produce.
	if err := grpcStatus(resp, method); err != nil {
		return nil, err
	}

	return unframe(body, method)
}

func grpcStatus(resp *http.Response, method string) error {
	status := resp.Header.Get("Grpc-Status")
	message := resp.Header.Get("Grpc-Message")

	if status == "" {
		status = resp.Trailer.Get("Grpc-Status")
		message = resp.Trailer.Get("Grpc-Message")
	}

	// No status at all is itself a problem: something answered that is not a
	// gRPC server, and reading its bytes as a container list would be worse than
	// failing.
	if status == "" {
		return fmt.Errorf("cri %s: no grpc-status in response", method)
	}

	code, err := strconv.Atoi(status)
	if err != nil {
		return fmt.Errorf("cri %s: unparseable grpc-status %q", method, status)
	}

	if code != 0 {
		return fmt.Errorf("cri %s: grpc status %d: %s", method, code, message)
	}

	return nil
}

// unframe strips the five-byte gRPC message prefix.
func unframe(body []byte, method string) ([]byte, error) {
	if len(body) < 5 {
		return nil, fmt.Errorf("cri %s: response too short (%d bytes)", method, len(body))
	}

	if body[0] != 0 {
		// Compression is only ever applied when the client advertised it, and
		// this client never does.
		return nil, fmt.Errorf("cri %s: unexpected compressed response", method)
	}

	size := binary.BigEndian.Uint32(body[1:5])
	if uint64(size) > uint64(len(body)-5) {
		return nil, fmt.Errorf("cri %s: truncated response: header says %d bytes, got %d", method, size, len(body)-5)
	}

	return body[5 : 5+size], nil
}
