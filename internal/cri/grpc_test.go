package cri

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"google.golang.org/protobuf/encoding/protowire"
)

// fakeCRI serves gRPC over a unix socket the way a container runtime does, so
// the transport is tested end to end — HTTP/2 over a unix socket, the five-byte
// message frame, and the grpc-status trailer — without needing a runtime.
type fakeCRI struct {
	// reply returns the response message for a method, or a non-zero gRPC status
	// code with a message.
	reply func(method string, request []byte) (response []byte, code int, text string)

	// omitStatus serves a response with no grpc-status at all, which is what a
	// plain HTTP server on the socket would do.
	omitStatus bool
}

// shortTempDir returns a directory short enough to hold a unix socket path.
//
// Not t.TempDir(): it embeds the test's name, and on macOS the result overruns
// the 104-byte limit on a socket path with "bind: invalid argument".
func shortTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "cri")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	return dir
}

// fakeServer is a running fakeCRI: the socket to dial, and a channel closed
// when the server side of a connection ends, so a test can assert the client
// released it.
type fakeServer struct {
	socket string
	ended  chan struct{}
}

func (f fakeCRI) start(t *testing.T) *fakeServer {
	t.Helper()

	server := &fakeServer{
		socket: filepath.Join(shortTempDir(t), "cri.sock"),
		ended:  make(chan struct{}, 8),
	}
	socket := server.socket

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	h2 := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		var request []byte
		if len(body) >= 5 {
			request = body[5:]
		}

		response, code, text := f.reply(r.URL.Path, request)

		w.Header().Set("Content-Type", "application/grpc")
		if !f.omitStatus {
			w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		}
		w.WriteHeader(http.StatusOK)

		if code == 0 {
			frame := make([]byte, 5+len(response))
			binary.BigEndian.PutUint32(frame[1:5], uint32(len(response)))
			copy(frame[5:], response)
			w.Write(frame)
		}

		if !f.omitStatus {
			w.Header().Set("Grpc-Status", strconv.Itoa(code))
			w.Header().Set("Grpc-Message", text)
		}
	})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Prior-knowledge h2c: the client starts speaking HTTP/2 straight
			// away, exactly as this package's client does.
			go func() {
				h2.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
				// ServeConn returns when the connection ends, which is how a
				// test sees that the client closed it.
				select {
				case server.ended <- struct{}{}:
				default:
				}
			}()
		}
	}()

	return server
}

// The whole transport, over a real unix socket: if this passes, the hand-rolled
// gRPC is talking the protocol a runtime speaks.
func TestAUnaryCallRoundTripsOverAUnixSocket(t *testing.T) {
	// One container, encoded the way a runtime would.
	container := protowire.AppendTag(nil, fContainerID, protowire.BytesType)
	container = protowire.AppendString(container, "abc123")
	container = protowire.AppendTag(container, fContainerState, protowire.VarintType)
	container = protowire.AppendVarint(container, stateRunning)

	list := protowire.AppendTag(nil, fListContainersContainers, protowire.BytesType)
	list = protowire.AppendBytes(list, container)

	var gotMethod string
	socket := fakeCRI{
		reply: func(method string, _ []byte) ([]byte, int, string) {
			gotMethod = method
			return list, 0, ""
		},
	}.start(t).socket

	response, err := dial(socket).call(context.Background(), methodListContainers, encodeListRunningContainers())
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if gotMethod != methodListContainers {
		t.Errorf("the server was asked for %q, want %q", gotMethod, methodListContainers)
	}

	containers, err := decodeListContainersResponse(response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(containers) != 1 || containers[0].ID != "abc123" {
		t.Errorf("round trip lost the container: %+v", containers)
	}
}

// A refused call must be an error and never an empty container list. This is
// the failure mode that would matter most: a runtime that denies the request —
// wrong socket permissions, an unimplemented method, a v2 interface — would
// otherwise make a node full of containers report as a node with none, and
// nothing in the inventory could tell that apart from a clean machine.
func TestARefusedCallIsAnErrorNotAnEmptyList(t *testing.T) {
	socket := fakeCRI{
		reply: func(string, []byte) ([]byte, int, string) {
			return nil, 7, "permission denied" // 7 is PERMISSION_DENIED
		},
	}.start(t).socket

	_, err := dial(socket).call(context.Background(), methodListContainers, encodeListRunningContainers())
	if err == nil {
		t.Fatal("a call the server refused returned no error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the error must carry what the runtime said; got %v", err)
	}
}

// Something is listening on the socket that is not a gRPC server. Reading its
// bytes as a container list would be worse than failing.
func TestAResponseWithoutAGrpcStatusIsAnError(t *testing.T) {
	socket := fakeCRI{
		omitStatus: true,
		reply: func(string, []byte) ([]byte, int, string) {
			return []byte("hello"), 0, ""
		},
	}.start(t).socket

	_, err := dial(socket).call(context.Background(), methodListContainers, encodeListRunningContainers())
	if err == nil || !strings.Contains(err.Error(), "grpc-status") {
		t.Errorf("want a missing-status error, got %v", err)
	}
}

// A socket that is not there at all is an ordinary error, not a panic or a hang.
func TestAnAbsentSocketIsAnError(t *testing.T) {
	_, err := dial(filepath.Join(shortTempDir(t), "nothing.sock")).call(
		context.Background(), methodListContainers, encodeListRunningContainers())

	if err == nil {
		t.Fatal("dialling a socket that does not exist returned no error")
	}
}

func TestUnframeRejectsWhatItCannotTrust(t *testing.T) {
	good := []byte{0, 0, 0, 0, 3, 'a', 'b', 'c'}
	if got, err := unframe(good, "/test"); err != nil || string(got) != "abc" {
		t.Errorf("unframe(good) = %q, %v", got, err)
	}

	cases := []struct {
		name string
		body []byte
	}{
		{"shorter than the frame header", []byte{0, 0, 0}},
		{"compressed, which this client never asks for", []byte{1, 0, 0, 0, 3, 'a', 'b', 'c'}},
		{"header claims more than arrived", []byte{0, 0, 0, 0, 9, 'a', 'b', 'c'}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := unframe(c.body, "/test"); err == nil {
				t.Error("accepted a frame it should have rejected")
			}
		})
	}
}
