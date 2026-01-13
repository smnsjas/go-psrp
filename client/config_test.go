package client

import (
	"testing"
)

func TestBuildResourceURI(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "Default",
			cfg:  Config{},
			want: "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
		},
		{
			name: "Custom ConfigurationName",
			cfg: Config{
				ConfigurationName: "JEAMaintenance",
			},
			want: "http://schemas.microsoft.com/powershell/JEAMaintenance",
		},
		{
			name: "ResourceURI Override",
			cfg: Config{
				ConfigurationName: "JEAMaintenance",
				ResourceURI:       "http://schemas.microsoft.com/powershell/Custom",
			},
			want: "http://schemas.microsoft.com/powershell/Custom",
		},
		{
			name: "Invalid ConfigurationName with Slash",
			cfg: Config{
				ConfigurationName: "Path/Traversal",
			},
			want: "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", // fallback
		},
		{
			name: "Invalid ConfigurationName with Backslash",
			cfg: Config{
				ConfigurationName: "Path\\Traversal",
			},
			want: "http://schemas.microsoft.com/powershell/Microsoft.PowerShell", // fallback
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a client with the config
			c := &Client{config: tt.cfg}
			if got := c.buildResourceURI(); got != tt.want {
				t.Errorf("buildResourceURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
