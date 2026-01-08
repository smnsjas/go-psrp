package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"golang.org/x/term"
)

func main() {
	server := flag.String("server", "", "WinRM server hostname")
	username := flag.String("user", "", "Username")
	password := flag.String("pass", "", "Password")
	useTLS := flag.Bool("tls", false, "Use HTTPS")
	insecure := flag.Bool("insecure", false, "Skip TLS verify")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")
	useKerberos := flag.Bool("kerberos", false, "Use Kerberos authentication")

	// Transport configuration
	transport := flag.String("transport", "wsman", "Transport type (wsman or hvsocket)")
	vmid := flag.String("vmid", "", "Hyper-V VM GUID (required for hvsocket)")

	concurrent := flag.Int("concurrent", 5, "Number of concurrent requests to spawn")
	maxRunspaces := flag.Int("max-runspaces", 2, "Client MaxRunspaces limit (semaphore size)")
	maxQueue := flag.Int("max-queue", 100, "Client MaxQueueSize limit")
	sleepSec := flag.Int("sleep", 2, "Seconds to sleep in each request")
	enableCBT := flag.Bool("cbt", false, "Enable Channel Binding Tokens (CBT) for NTLM (Extended Protection)")
	logLevel := flag.String("loglevel", "", "Log level: debug, info, warn, error")

	flag.Parse()

	// Validate required flags based on transport
	if *transport == "wsman" {
		if *server == "" || *username == "" {
			fmt.Println("Usage: go run main.go -transport wsman -server <host> -user <user> [options]")
			flag.PrintDefaults()
			os.Exit(1)
		}
	} else if *transport == "hvsocket" {
		if *vmid == "" {
			fmt.Println("Usage: go run main.go -transport hvsocket -vmid <guid> [options]")
			flag.PrintDefaults()
			os.Exit(1)
		}
	} else {
		fmt.Printf("Unknown transport: %s\n", *transport)
		os.Exit(1)
	}

	pass := getPassword(*password)

	cfg := client.DefaultConfig()
	cfg.Username = *username
	cfg.Password = pass
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	cfg.MaxRunspaces = *maxRunspaces
	cfg.MaxQueueSize = *maxQueue
	cfg.EnableCBT = *enableCBT

	if *logLevel != "" {
		var level slog.Level
		switch strings.ToLower(*logLevel) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			fmt.Fprintf(os.Stderr, "Invalid log level '%s'\n", *logLevel)
			os.Exit(1)
		}
		// Set env var for legacy debug
		if level == slog.LevelDebug {
			os.Setenv("PSRP_DEBUG", "1")
		}
	}

	if *useTLS {
		cfg.Port = 5986
	}

	if *useKerberos {
		cfg.AuthType = client.AuthKerberos
	} else if *useNTLM {
		cfg.AuthType = client.AuthNTLM
	}

	target := *server
	if *transport == "hvsocket" {
		cfg.Transport = client.TransportHvSocket
		cfg.VMID = *vmid
		target = *vmid // client.New expects target to be VMID for HvSocket (or hostname for WSMan)
		fmt.Printf("Creating HvSocket client to VM %s (MaxRunspaces=%d)...\n", *vmid, *maxRunspaces)
	} else {
		fmt.Printf("Creating WSMan client to %s (Auth: %v, MaxRunspaces=%d)...\n", *server, cfg.AuthType, *maxRunspaces)
	}

	c, err := client.New(target, cfg)
	if err != nil {
		panic(err)
	}

	if *logLevel != "" {
		// Re-parse level to create logger (simplified)
		var level slog.Level
		switch strings.ToLower(*logLevel) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
		c.SetSlogLogger(logger)
	}

	defer c.Close(context.Background())

	fmt.Println("Connecting...")
	if err := c.Connect(context.Background()); err != nil {
		panic(err)
	}

	fmt.Printf("Spawning %d concurrent requests (each sleeps %ds)...\n", *concurrent, *sleepSec)
	fmt.Println("Observe: Only", *maxRunspaces, "should run at once.")
	fmt.Println("---------------------------------------------------")

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < *concurrent; i++ {
		wg.Add(1)
		id := i + 1
		go func(id int) {
			defer wg.Done()

			// Script calls Start-Sleep
			script := fmt.Sprintf("Write-Output 'Start %d'; Start-Sleep -Seconds %d; Write-Output 'End %d'", id, *sleepSec, id)

			reqStart := time.Now()
			// fmt.Printf("[%s] Req %d: Queued\n", time.Since(start).Round(time.Millisecond), id)

			res, err := c.Execute(context.Background(), script)

			duration := time.Since(reqStart)
			if err != nil {
				fmt.Printf("[%s] Req %d: ERROR: %v\n", time.Since(start).Round(time.Millisecond), id, err)
				return
			}

			// Show output to confirm it ran
			output := ""
			if len(res.Output) > 0 {
				output = fmt.Sprintf("%v", res.Output)
			}

			fmt.Printf("[%s] Req %d: Finished in %s. Output: %s\n",
				time.Since(start).Round(time.Millisecond), id, duration.Round(time.Millisecond), output)
		}(id)
	}

	wg.Wait()
	fmt.Println("---------------------------------------------------")
	fmt.Println("All done.")
}

// getPassword returns password from flag, env var, or prompts for it.
func getPassword(flagValue string) string {
	// 1. Check flag
	if flagValue != "" {
		return flagValue
	}

	// 2. Check environment variable
	if envPass := os.Getenv("PSRP_PASSWORD"); envPass != "" {
		return envPass
	}

	// 3. Prompt for password (hide input if terminal)
	fmt.Fprint(os.Stderr, "Password: ")

	// Use os.Stdin.Fd() cast to int for cross-platform compatibility
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		// Terminal: read password without echo
		passBytes, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // newline after password
		if err != nil {
			return ""
		}
		return string(passBytes)
	}

	// Not a terminal (piped input): read line
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}
