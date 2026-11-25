package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/kilo666mj/switchboard/internal/capability"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Bound capability views share this connection, but each tool call supplies
// its own authenticated request context.
type upstreamSession struct {
	name    string
	ctx     context.Context
	cancel  context.CancelFunc
	connect func(context.Context) (*mcp.ClientSession, error)

	mu      sync.Mutex
	active  *mcp.ClientSession
	pending chan struct{}
	retryAt time.Time
	backoff time.Duration
}

func (b toolBinding) readOnly() bool {
	a := b.definition.Annotations
	return a != nil && a.ReadOnlyHint && (a.DestructiveHint == nil || !*a.DestructiveHint)
}

func (c *Capability) callTool(ctx context.Context, binding toolBinding, arguments any) (*mcp.CallToolResult, error) {
	ctx = c.callContext(ctx)
	params := &mcp.CallToolParams{Name: binding.upstream, Arguments: arguments}
	for attempt := 0; ; attempt++ {
		session, err := c.upstream.get(ctx)
		if err != nil {
			return nil, err
		}
		result, err := session.CallTool(ctx, params)
		if !errors.Is(err, mcp.ErrConnectionClosed) && !errors.Is(err, mcp.ErrSessionMissing) {
			return result, err
		}
		c.upstream.invalidate(session)
		if attempt != 0 || !binding.readOnly() || ctx.Err() != nil {
			return result, err
		}
	}
}

func (s *upstreamSession) get(ctx context.Context) (*mcp.ClientSession, error) {
	for {
		s.mu.Lock()
		if err := s.ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if session := s.active; session != nil {
			s.mu.Unlock()
			return session, nil
		}
		if time.Now().Before(s.retryAt) {
			s.mu.Unlock()
			return nil, fmt.Errorf("%w: %s MCP reconnect failed", capability.ErrUnavailable, s.name)
		}
		if s.pending == nil {
			s.startReconnectLocked(nil)
		}
		pending := s.pending
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending:
		}
	}
}

func (s *upstreamSession) invalidate(failed *mcp.ClientSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A delayed error from an older generation must not evict its replacement.
	if s.active == failed && s.ctx.Err() == nil {
		s.active = nil
		s.startReconnectLocked(failed)
	}
}

func (s *upstreamSession) startReconnectLocked(old *mcp.ClientSession) {
	s.pending = make(chan struct{})
	go func() {
		if old != nil {
			_ = old.Close()
		}
		ctx, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
		defer cancel()
		next, err := s.connect(ctx)
		s.mu.Lock()
		defer s.mu.Unlock()
		defer func() {
			close(s.pending)
			s.pending = nil
		}()
		if s.ctx.Err() != nil {
			if next != nil {
				_ = next.Close()
			}
			return
		}
		if err != nil {
			s.backoff = min(max(5*time.Second, 2*s.backoff), 5*time.Minute)
			s.retryAt = time.Now().Add(s.backoff)
			slog.Warn("upstream MCP reconnect failed", "capability", s.name, "retry_in", s.backoff)
			return
		}
		s.active = next
		s.retryAt = time.Time{}
		s.backoff = 0
		slog.Info("upstream MCP reconnected", "capability", s.name)
	}()
}

func (s *upstreamSession) close() error {
	s.mu.Lock()
	s.cancel()
	session, pending := s.active, s.pending
	s.active = nil
	s.mu.Unlock()
	if pending != nil {
		<-pending
	}
	if session != nil {
		return session.Close()
	}
	return nil
}
