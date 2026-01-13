package client

import (
	"strings"
)

// buildResourceURI constructs the WSMan ResourceURI from config.
// It prioritizes explicit ResourceURI overrides, then constructs from ConfigurationName.
func (c *Client) buildResourceURI() string {
	// Priority: ResourceURI > ConfigurationName > Default
	if c.config.ResourceURI != "" {
		return c.config.ResourceURI
	}

	const base = "http://schemas.microsoft.com/powershell/"
	if c.config.ConfigurationName != "" {
		// Validate ConfigurationName (no path separators/special chars logic if needed)
		// For now, we trust it but ensure it's not trying to escape protocol scheme
		if strings.Contains(c.config.ConfigurationName, "/") || strings.Contains(c.config.ConfigurationName, "\\") {
			c.logWarn("ConfigurationName contains path separators, using default (name=%s)", c.config.ConfigurationName)
			return base + "Microsoft.PowerShell"
		}
		return base + c.config.ConfigurationName
	}

	return base + "Microsoft.PowerShell"
}
