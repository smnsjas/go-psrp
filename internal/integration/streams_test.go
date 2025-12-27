//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrpcore/serialization"
)

func TestStreams(t *testing.T) {
	// Use environment variables or defaults matching your setup
	host := os.Getenv("PSRP_SERVER")
	if host == "" {
		host = "10.211.55.6"
	}
	port := 5985
	user := "winrm-test"
	pass := "sigK@@6=q8B2z8iQDzbiqJr4"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Connect
	c, err := client.New(host, client.Config{
		Port:               port,
		UseTLS:             false,
		InsecureSkipVerify: true,
		Timeout:            30 * time.Second,
		AuthType:           client.AuthNTLM,
		Username:           user,
		Password:           pass,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if err := c.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() {
		// Create a new context for close in case the main one is canceled/timed out
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Close(closeCtx)
	}()

	// 2. Execute script emitting all streams
	script := `
		Write-Output "output message"
		Write-Warning "warning message"
		Write-Verbose "verbose message" -Verbose
		Write-Debug "debug message" -Debug
		Write-Information "information message" -InformationAction Continue
		Write-Progress -Activity "Testing" -Status "In Progress" -PercentComplete 50
	`

	result, err := c.Execute(ctx, script)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	// 3. Verify Output
	checkStream(t, "Output", result.Output, "output message")

	// 4. Verify Warning
	checkStream(t, "Warning", result.Warnings, "warning message")

	// 5. Verify Verbose
	checkStream(t, "Verbose", result.Verbose, "verbose message")

	// 6. Verify Debug
	checkStream(t, "Debug", result.Debug, "debug message")

	// 7. Verify Information
	// Information records are complex objects, check ToString or Properties
	foundInfo := false
	for _, item := range result.Information {
		if ps, ok := item.(*serialization.PSObject); ok {
			// InformationRecord wraps the message data
			if ps.ToString == "information message" {
				foundInfo = true
				break
			}
			// Often the message is in MessageData property for InformationRecord
			if msgData, ok := ps.Properties["MessageData"]; ok {
				// MessageData can be a string or a PSObject wrapping the data
				if str, ok := msgData.(string); ok && str == "information message" {
					foundInfo = true
					break
				}
				if psData, ok := msgData.(*serialization.PSObject); ok {
					if psData.ToString == "information message" {
						foundInfo = true
						break
					}
				}
			}
		}
	}
	if !foundInfo {
		t.Errorf("Expected 'information message' in Information stream, got: %v", result.Information)
	}

	// 8. Verify Progress
	foundProgress := false
	for _, item := range result.Progress {
		if ps, ok := item.(*serialization.PSObject); ok {
			// Simple check for Activity/Status
			props := ps.Properties
			if activity, ok := props["Activity"]; ok && fmt.Sprint(activity) == "Testing" {
				foundProgress = true
				break
			}
		}
	}
	if !foundProgress {
		t.Errorf("Expected progress record with Activity='Testing', got: %v", result.Progress)
	}
}

func checkStream(t *testing.T, name string, stream []interface{}, expected string) {
	found := false
	for _, item := range stream {
		// Handle both string and PSObject wrapping
		val := fmt.Sprint(item)
		if ps, ok := item.(*serialization.PSObject); ok {
			if ps.ToString != "" {
				val = ps.ToString
			} else {
				// Some records like WarningRecord wrap the message in a "Message" property
				if msg, ok := ps.Properties["Message"]; ok {
					val = fmt.Sprint(msg)
				}
			}
		}

		if val == expected {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected '%s' in %s stream, got: %v", expected, name, stream)
	}
}
