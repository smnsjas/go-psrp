// Command psrp-client is an example PowerShell Remoting client.
//
// Password can be provided via:
//   - -pass flag (least secure, visible in process list)
//   - PSRP_PASSWORD environment variable (recommended)
//   - stdin prompt (if neither flag nor env var is set)
//
// Usage:
//
//	psrp-client -server <hostname> -user <username> -script <command>
//
// Examples:
//
//	# Using environment variable (recommended)
//	export PSRP_PASSWORD='secret'
//	psrp-client -server myserver -user admin -script "Get-Process"
//
//	# Using stdin prompt
//	psrp-client -server myserver -user admin -script "Get-Process"
//	Password: ********
//
//	# Using flag (not recommended, visible in process list)
//	psrp-client -server myserver -user admin -pass secret -script "Get-Process"
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/smnsjas/go-psrp/client"
	"github.com/smnsjas/go-psrpcore/serialization"
	"golang.org/x/term"
)

func main() {
	// Parse command line flags
	server := flag.String("server", "", "WinRM server hostname")
	username := flag.String("user", "", "Username for authentication")
	password := flag.String("pass", "", "Password (use PSRP_PASSWORD env var instead)")
	script := flag.String("script", "Get-Process | Select-Object -First 5", "PowerShell script to execute")
	useTLS := flag.Bool("tls", false, "Use HTTPS (port 5986)")
	port := flag.Int("port", 0, "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	timeout := flag.Duration("timeout", 60*time.Second, "Operation timeout")
	useNTLM := flag.Bool("ntlm", false, "Use NTLM authentication")
	useKerberos := flag.Bool("kerberos", false, "Use Kerberos authentication")
	realm := flag.String("realm", "", "Kerberos realm (e.g., EXAMPLE.COM)")
	krb5Conf := flag.String("krb5conf", "", "Path to krb5.conf file")
	ccache := flag.String("ccache", "", "Path to Kerberos credential cache (e.g. /tmp/krb5cc_1000)")

	flag.Parse()

	// Validate required flags
	if *server == "" {
		fmt.Fprintln(os.Stderr, "Error: -server is required")
		flag.Usage()
		os.Exit(1)
	}
	if *username == "" {
		fmt.Fprintln(os.Stderr, "Error: -user is required")
		flag.Usage()
		os.Exit(1)
	}

	// Check for Kerberos cred cache first (SSO)
	var pass string
	hasCache := *ccache != "" || os.Getenv("KRB5CCNAME") != ""

	// Get password unless we have a Kerberos cache (applicable to both -kerberos and default AuthNegotiate)
	if !hasCache {
		// Get password from: flag > env var > stdin prompt
		pass = getPassword(*password)
	}

	// Password is required unless: using Kerberos with cache, or explicit -kerberos flag with cache
	if pass == "" && !hasCache {
		fmt.Fprintln(os.Stderr, "Error: password is required (use -pass, PSRP_PASSWORD env, or stdin)")
		os.Exit(1)
	}

	// Build configuration
	cfg := client.DefaultConfig()
	cfg.Username = *username
	cfg.Password = pass
	cfg.UseTLS = *useTLS
	cfg.InsecureSkipVerify = *insecure
	cfg.Timeout = *timeout

	// Kerberos settings apply to both AuthNegotiate (default) and explicit -kerberos
	cfg.Realm = *realm
	cfg.Krb5ConfPath = *krb5Conf
	cfg.CCachePath = *ccache
	// Default to environment variables if flags not set
	if cfg.CCachePath == "" {
		cfg.CCachePath = os.Getenv("KRB5CCNAME")
	}
	if cfg.Realm == "" {
		cfg.Realm = os.Getenv("PSRP_REALM")
	}
	if cfg.Krb5ConfPath == "" {
		cfg.Krb5ConfPath = os.Getenv("KRB5_CONFIG")
	}

	// Override auth type if explicit flag set
	if *useKerberos {
		cfg.AuthType = client.AuthKerberos
	} else if *useNTLM {
		cfg.AuthType = client.AuthNTLM
	}
	// Default is AuthNegotiate (set by DefaultConfig)

	// Set port
	if *port != 0 {
		cfg.Port = *port
	} else if *useTLS {
		cfg.Port = 5986
	}

	// Create client
	psrp, err := client.New(*server, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Connect to server
	fmt.Printf("Connecting to %s...\n", psrp.Endpoint())
	if err := psrp.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting: %v\n", err)
		os.Exit(1)
	}
	defer psrp.Close(ctx)

	fmt.Println("Connected!")

	// Execute script
	fmt.Printf("Executing: %s\n", *script)
	fmt.Println("---")

	result, err := psrp.Execute(ctx, *script)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing script: %v\n", err)
		os.Exit(1)
	}

	// Print output - format each object for display
	fmt.Println("Output:")
	for _, obj := range result.Output {
		fmt.Println(formatObject(obj))
	}

	if result.HadErrors {
		fmt.Fprintln(os.Stderr, "Errors:")
		for _, obj := range result.Errors {
			fmt.Fprintln(os.Stderr, formatObject(obj))
		}
		os.Exit(1)
	}
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

	if term.IsTerminal(syscall.Stdin) {
		// Terminal: read password without echo
		passBytes, err := term.ReadPassword(syscall.Stdin)
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

// formatObject converts a deserialized CLIXML object to a human-readable string.
func formatObject(v interface{}) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case string:
		// Decode XML-encoded CRLF (from PowerShell/CLIXML) for cleaner display
		result := val
		result = strings.ReplaceAll(result, "_x000D__x000A_", "\n")
		result = strings.ReplaceAll(result, "_x000D_", "\r")
		result = strings.ReplaceAll(result, "_x000A_", "\n")
		return result
	case *serialization.PSObject:
		// For PSObjects, use ToString if available, otherwise format properties
		if val.ToString != "" {
			return val.ToString
		}
		// Fallback: format as key=value pairs with recursive formatting
		var parts []string
		for k, prop := range val.Properties {
			parts = append(parts, fmt.Sprintf("%s=%s", k, formatObject(prop)))
		}
		return strings.Join(parts, " ")
	case []interface{}:
		// Format slices recursively
		var items []string
		for _, item := range val {
			items = append(items, formatObject(item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case bool:
		return fmt.Sprintf("%t", val)
	case int32, int64, float64:
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", v)
	}
}
