package wsman

import "encoding/xml"

// EndpointReference represents a WS-Addressing Endpoint Reference (EPR).
// It identifies the created shell instance on the server.
type EndpointReference struct {
	Address     string     `xml:"Address"`
	ResourceURI string     `xml:"ReferenceParameters>ResourceURI"`
	Selectors   []Selector `xml:"ReferenceParameters>SelectorSet>Selector"`
}

// Selector represents a WS-Management selector.
type Selector struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// Subscribe represents the body of a Subscribe request.
type Subscribe struct {
	XMLName  xml.Name `xml:"wse:Subscribe"`
	Wse      string   `xml:"xmlns:wse,attr"`
	Delivery Delivery `xml:"wse:Delivery"`
	Expires  string   `xml:"wse:Expires,omitempty"` // ISO 8601 Duration (e.g. PT10M)
	Filter   Filter   `xml:"w:Filter"`
}

// Delivery represents the event delivery mode.
type Delivery struct {
	Mode string `xml:"Mode,attr"`
}

// Filter represents the event subscription filter.
type Filter struct {
	Dialect string `xml:"Dialect,attr"` // e.g. http://schemas.microsoft.com/wbem/wsman/1/WQL
	Query   string `xml:",chardata"`
}

// SubscribeResponse represents the response to a Subscribe request.
type SubscribeResponse struct {
	XMLName             xml.Name          `xml:"SubscribeResponse"`
	SubscriptionManager EndpointReference `xml:"SubscriptionManager"`
	Expires             string            `xml:"Expires"`
	EnumerationContext  string            `xml:"EnumerationContext"` // For Pull mode
}

// Unsubscribe represents the body of an Unsubscribe request.
type Unsubscribe struct {
	XMLName xml.Name `xml:"wse:Unsubscribe"`
	Wse     string   `xml:"xmlns:wse,attr"`
}

// Pull represents the body of a Pull request (Enumeration or Eventing).
type Pull struct {
	XMLName            xml.Name `xml:"wsen:Pull"`
	Wsen               string   `xml:"xmlns:wsen,attr"`
	EnumerationContext string   `xml:"wsen:EnumerationContext"`
	MaxElements        int      `xml:"wsen:MaxElements,omitempty"`
	MaxTime            string   `xml:"wsen:MaxTime,omitempty"` // ISO 8601 Duration
}

// PullResponse represents the response to a Pull request.
type PullResponse struct {
	XMLName            xml.Name `xml:"PullResponse"`
	EnumerationContext string   `xml:"EnumerationContext"`
	Items              Items    `xml:"Items"`
	EndOfSequence      *string  `xml:"EndOfSequence"` // Present if no more items
}

// Items contains the pulled elements (raw XML).
type Items struct {
	Raw []byte `xml:",innerxml"`
}

// Subscription represents an active event subscription.
type Subscription struct {
	SubscriptionID     string
	EnumerationContext string
	Expires            string
	Manager            *EndpointReference
}
