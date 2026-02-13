package wsman

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/smnsjas/go-psrp/wsman/transport"
)

// sendOKResponse writes a minimal valid SOAP response for Send operations.
func sendOKResponse(w http.ResponseWriter) {
	resp := `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <rsp:SendResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"/>
  </s:Body>
</s:Envelope>`
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(resp))
}

// TestSendMulti_TableDriven covers the core chunking logic with table-driven tests.
func TestSendMulti_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		dataSlices       [][]byte
		maxSendSize      int
		maxStreams       int
		wantHTTPRequests int
		wantStreams      []int // per-request stream counts
	}{
		{
			name:             "empty_input_noop",
			dataSlices:       nil,
			wantHTTPRequests: 0,
		},
		{
			name:             "single_item_delegates_to_send",
			dataSlices:       [][]byte{[]byte("hello")},
			wantHTTPRequests: 1,
			wantStreams:      []int{1},
		},
		{
			name: "two_items_one_batch",
			dataSlices: [][]byte{
				[]byte("item-1"),
				[]byte("item-2"),
			},
			wantHTTPRequests: 1,
			wantStreams:      []int{2},
		},
		{
			name: "five_items_max_two_per_batch",
			dataSlices: [][]byte{
				[]byte("a"), []byte("b"), []byte("c"),
				[]byte("d"), []byte("e"),
			},
			maxStreams:       2,
			wantHTTPRequests: 3,
			wantStreams:      []int{2, 2, 1},
		},
		{
			name: "exact_boundary_count",
			dataSlices: [][]byte{
				[]byte("a"), []byte("b"), []byte("c"), []byte("d"),
			},
			maxStreams:       2,
			wantHTTPRequests: 2,
			wantStreams:      []int{2, 2},
		},
		{
			name: "size_limit_triggers_flush",
			dataSlices: [][]byte{
				make([]byte, 100),
				make([]byte, 100),
				make([]byte, 100),
			},
			// streamOverhead(150) + base64Len(136) = 286 per stream
			// sendWrapOverhead = 100
			// maxSendSize = 500 → fits 1 stream (100+286=386), second would exceed (386+286=672>500)
			maxSendSize:      500,
			wantHTTPRequests: 3,
			wantStreams:      []int{1, 1, 1},
		},
		{
			name: "single_oversize_item_still_sends",
			dataSlices: [][]byte{
				make([]byte, 10000), // Much larger than maxSendSize
			},
			maxSendSize:      100,
			wantHTTPRequests: 1,
			wantStreams:      []int{1},
		},
		{
			name: "both_limits_interact",
			dataSlices: [][]byte{
				[]byte("a"), []byte("b"), []byte("c"),
				[]byte("d"), []byte("e"), []byte("f"),
			},
			maxStreams:       3,
			maxSendSize:      DefaultMaxSendSize, // won't trigger
			wantHTTPRequests: 2,
			wantStreams:      []int{3, 3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requestCount int32
			var bodies []string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&requestCount, 1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("reading request body: %v", err)
				}
				bodies = append(bodies, string(body))
				sendOKResponse(w)
			}))
			defer server.Close()

			client := NewClient(server.URL, transport.NewHTTPTransport())
			if tc.maxSendSize > 0 {
				client.MaxSendSize = tc.maxSendSize
			}
			if tc.maxStreams > 0 {
				client.MaxStreamsPerSend = tc.maxStreams
			}

			err := client.SendMulti(
				context.Background(),
				dummyEPR(),
				"cmd-id",
				"stdin",
				tc.dataSlices,
			)
			if err != nil {
				t.Fatalf("SendMulti() error = %v", err)
			}

			gotRequests := int(atomic.LoadInt32(&requestCount))
			if gotRequests != tc.wantHTTPRequests {
				t.Errorf("HTTP requests = %d, want %d", gotRequests, tc.wantHTTPRequests)
			}

			// Verify per-request stream counts
			if tc.wantStreams != nil && len(bodies) == len(tc.wantStreams) {
				for i, body := range bodies {
					gotStreams := strings.Count(body, "<rsp:Stream")
					if gotStreams != tc.wantStreams[i] {
						t.Errorf("request[%d]: streams = %d, want %d",
							i, gotStreams, tc.wantStreams[i])
					}
				}
			}
		})
	}
}

// TestSendMulti_DataIntegrity verifies that all data is correctly
// base64-encoded and arrives at the server across chunked batches.
func TestSendMulti_DataIntegrity(t *testing.T) {
	var allBodies []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading body: %v", err)
		}
		allBodies = append(allBodies, string(body))
		sendOKResponse(w)
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())
	client.MaxStreamsPerSend = 3

	// Send 7 items — will chunk into 3+3+1
	items := make([][]byte, 7)
	for i := range items {
		items[i] = []byte("data-" + string(rune('A'+i)))
	}

	if err := client.SendMulti(context.Background(), dummyEPR(), "cmd-id", "stdin", items); err != nil {
		t.Fatalf("SendMulti() error = %v", err)
	}

	if len(allBodies) != 3 {
		t.Fatalf("got %d requests, want 3", len(allBodies))
	}

	// Extract all base64 stream contents and decode
	var decoded []string
	for _, body := range allBodies {
		// Find all stream content between <rsp:Stream ...> and </rsp:Stream>
		parts := strings.Split(body, "<rsp:Stream")
		for _, part := range parts[1:] { // skip first empty part
			start := strings.Index(part, ">")
			end := strings.Index(part, "</rsp:Stream>")
			if start < 0 || end < 0 || start >= end {
				t.Fatalf("malformed stream element in body")
			}
			b64 := part[start+1 : end]
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				t.Fatalf("base64 decode failed: %v", err)
			}
			decoded = append(decoded, string(raw))
		}
	}

	if len(decoded) != 7 {
		t.Fatalf("decoded %d items, want 7", len(decoded))
	}
	for i, got := range decoded {
		want := "data-" + string(rune('A'+i))
		if got != want {
			t.Errorf("item[%d] = %q, want %q", i, got, want)
		}
	}
}

// TestSendMulti_ContextCancellation verifies that a cancelled context
// prevents sending.
func TestSendMulti_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sendOKResponse(w)
	}))
	defer server.Close()

	client := NewClient(server.URL, transport.NewHTTPTransport())
	client.MaxStreamsPerSend = 1

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	items := [][]byte{[]byte("a"), []byte("b")}
	err := client.SendMulti(ctx, dummyEPR(), "cmd-id", "stdin", items)
	if err == nil {
		t.Fatal("SendMulti() should fail with cancelled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error = %v, want context canceled", err)
	}
}

// TestSendMulti_CommandIDInStreams verifies that CommandId is included
// when non-empty and omitted when empty.
func TestSendMulti_CommandIDInStreams(t *testing.T) {
	tests := []struct {
		name      string
		commandID string
		wantAttr  bool
	}{
		{"with_command_id", "test-cmd-id", true},
		{"without_command_id", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var receivedBody string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("reading body: %v", err)
				}
				receivedBody = string(body)
				sendOKResponse(w)
			}))
			defer server.Close()

			client := NewClient(server.URL, transport.NewHTTPTransport())
			items := [][]byte{[]byte("a"), []byte("b")}

			err := client.SendMulti(context.Background(), dummyEPR(), tc.commandID, "stdin", items)
			if err != nil {
				t.Fatalf("SendMulti() error = %v", err)
			}

			hasAttr := strings.Contains(receivedBody, `CommandId="`)
			if hasAttr != tc.wantAttr {
				t.Errorf("CommandId present = %v, want %v", hasAttr, tc.wantAttr)
			}
		})
	}
}
