package wsman

// EndpointReference represents a WS-Addressing Endpoint Reference (EPR).
// It identifies the created shell instance on the server.
type EndpointReference struct {
	Address     string
	ResourceURI string
	Selectors   []Selector
}

// Selector represents a WS-Management selector.
type Selector struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}
