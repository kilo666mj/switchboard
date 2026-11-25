package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.michaelspost.com/mcpkit"
	"go.michaelspost.com/mcpkit/mcpkittest"
)

// Drop the response after the upstream has executed the operation. This makes
// accidental replay of a write observable even though the caller saw an error.
func TestRecoveryAfterLostToolResponse(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations *mcp.ToolAnnotations
		wantCalls   int32
	}{
		{"read", mcpkit.ReadOnly(false), 2},
		{"write", mcpkit.Mutating(false, false), 1},
		{"unannotated", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var executions, handshakes atomic.Int32
			var lost atomic.Bool
			server := mcpkit.MustServer(mcpkit.ServerConfig{Name: "upstream", Version: "test"})
			mcp.AddTool(server, &mcp.Tool{Name: "operation", Annotations: tc.annotations},
				func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
					executions.Add(1)
					return &mcp.CallToolResult{}, nil, nil
				})
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					var rpc struct{ Method string }
					_ = json.Unmarshal(body, &rpc)
					if rpc.Method == "initialize" {
						handshakes.Add(1)
					}
					if rpc.Method == "tools/call" && lost.CompareAndSwap(false, true) {
						handler.ServeHTTP(httptest.NewRecorder(), r)
						http.Error(w, "session expired", http.StatusNotFound)
						return
					}
				}
				handler.ServeHTTP(w, r)
			}))
			defer api.Close()
			item, err := New(t.Context(), Manifest{Version: 1, Type: "mcp", Name: "demo", Endpoint: api.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer item.Close()
			initial := handshakes.Load()
			gateway := mcpkit.MustServer(mcpkit.ServerConfig{Name: "gateway", Version: "test"})
			if err := item.Register(gateway); err != nil {
				t.Fatal(err)
			}
			session := mcpkittest.Connect(t, gateway)
			call := func() bool {
				result, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "demo_operation", Arguments: map[string]any{}})
				return err == nil && !result.IsError
			}
			if got := call(); got != (tc.name == "read") {
				t.Errorf("first call succeeded = %v", got)
			}
			if got := executions.Load(); got != tc.wantCalls {
				t.Fatalf("first call executed %d times, want %d", got, tc.wantCalls)
			}
			if !call() {
				t.Fatal("next call failed")
			}
			if got := handshakes.Load() - initial; got != 1 {
				t.Errorf("got %d new handshakes, want one", got)
			}
		})
	}
}

func TestSharedReconnectFailureAndBackoff(t *testing.T) {
	var attempts atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	errDenied := errors.New("upstream denied handshake")
	ctx, cancel := context.WithCancel(t.Context())
	s := &upstreamSession{ctx: ctx, cancel: cancel, connect: func(context.Context) (*mcp.ClientSession, error) {
		if attempts.Add(1) == 1 {
			close(started)
			<-release
		}
		return nil, errDenied
	}}
	defer s.close()
	const n = 8
	results := make(chan error, n)
	for range n {
		go func() {
			_, err := s.get(ctx)
			results <- err
		}()
	}
	<-started
	waitCtx, stop := context.WithCancel(ctx)
	stop()
	if _, err := s.get(waitCtx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait: %v", err)
	}
	close(release)
	for range n {
		if err := <-results; !errors.Is(err, capability.ErrUnavailable) {
			t.Fatal(err)
		}
	}
	if _, err := s.get(ctx); !errors.Is(err, capability.ErrUnavailable) {
		t.Fatal(err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("attempts during backoff = %d", attempts.Load())
	}
	s.mu.Lock()
	s.retryAt = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if _, err := s.get(ctx); !errors.Is(err, capability.ErrUnavailable) {
		t.Fatal(err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts after cooldown = %d", attempts.Load())
	}
}

func TestPollRecoversAfterUnauthorizedClosesTransport(t *testing.T) {
	var lists, calls atomic.Int32
	var denyTool atomic.Bool
	server := mcpkit.MustServer(mcpkit.ServerConfig{Name: "source", Version: "test"})
	mcp.AddTool(server, &mcp.Tool{Name: "poll", Annotations: mcpkit.ReadOnly(false)},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			if denyTool.Load() {
				return nil, nil, errors.New("operator permission required")
			}
			return &mcp.CallToolResult{}, nil, nil
		})
	handler, err := mcpkit.StatelessHTTP(func(*http.Request) *mcp.Server { return server }, mcpkit.HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var rpc struct{ Method string }
			_ = json.Unmarshal(body, &rpc)
			switch rpc.Method {
			case "tools/list":
				lists.Add(1)
			case "tools/call":
				if calls.Add(1) == 1 {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer api.Close()
	item, err := New(t.Context(), Manifest{Version: 1, Type: "mcp", Name: "source", Endpoint: api.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer item.Close()
	poll := func() (*mcp.CallToolResult, error) {
		return item.ExecuteReadOnly(t.Context(), "source_poll", map[string]any{})
	}
	// The first 401 may be reported directly. The next poll must recover even
	// when the SDK now returns ErrConnectionClosed wrapped around that 401.
	_, _ = poll()
	if result, err := poll(); err != nil || result.IsError {
		t.Fatalf("poll after 401: %v, %v", result, err)
	}
	if lists.Load() != 2 {
		t.Fatalf("catalogs loaded = %d, want 2", lists.Load())
	}
	denyTool.Store(true)
	before := calls.Load()
	if result, err := poll(); err != nil || !result.IsError {
		t.Fatalf("tool denial: %v, %v", result, err)
	}
	if calls.Load() != before+1 || lists.Load() != 2 {
		t.Fatal("ordinary permission denial triggered recovery or replay")
	}
}
