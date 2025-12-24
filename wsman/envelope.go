package wsman

import (
	"encoding/xml"
)

// Envelope represents a SOAP 1.2 envelope for WS-Management messages.
type Envelope struct {
	XMLName xml.Name `xml:"s:Envelope"`

	// Namespace declarations
	NsSoap    string `xml:"xmlns:s,attr"`
	NsAddr    string `xml:"xmlns:a,attr"`
	NsWsman   string `xml:"xmlns:w,attr"`
	NsMsWsman string `xml:"xmlns:p,attr"`
	NsShellNs string `xml:"xmlns:rsp,attr,omitempty"`
	NsXsiAttr string `xml:"xmlns:xsi,attr,omitempty"`

	Header *Header `xml:"s:Header"`
	Body   *Body   `xml:"s:Body"`
}

// Header represents the SOAP header containing WS-Addressing and WS-Management headers.
type Header struct {
	// WS-Addressing headers
	Action    string   `xml:"a:Action,omitempty"`
	To        string   `xml:"a:To,omitempty"`
	MessageID string   `xml:"a:MessageID,omitempty"`
	ReplyTo   *ReplyTo `xml:"a:ReplyTo,omitempty"`

	// WS-Management headers
	ResourceURI      string `xml:"w:ResourceURI,omitempty"`
	MaxEnvelopeSize  int    `xml:"w:MaxEnvelopeSize,omitempty"`
	OperationTimeout string `xml:"w:OperationTimeout,omitempty"`
	Locale           string `xml:"p:Locale,omitempty"`
	DataLocale       string `xml:"p:DataLocale,omitempty"`

	// Shell-specific headers
	SelectorSet *SelectorSet `xml:"w:SelectorSet,omitempty"`
	OptionSet   *OptionSet   `xml:"w:OptionSet,omitempty"`
}

// ReplyTo represents the WS-Addressing ReplyTo element.
type ReplyTo struct {
	Address string `xml:"a:Address"`
}

// SelectorSet contains selectors for targeting specific resources.
type SelectorSet struct {
	Selectors []Selector `xml:"w:Selector"`
}

// Selector represents a single selector key-value pair.
type Selector struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// OptionSet contains options for the operation.
type OptionSet struct {
	Options []Option `xml:"w:Option"`
}

// Option represents a single option.
type Option struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// Body represents the SOAP body.
type Body struct {
	Content []byte `xml:",innerxml"`
}

// NewEnvelope creates a new SOAP envelope with required namespace declarations.
func NewEnvelope() *Envelope {
	return &Envelope{
		NsSoap:    NsSoap,
		NsAddr:    NsAddressing,
		NsWsman:   NsWsman,
		NsMsWsman: NsWsmanMicrosoft,
		Header:    &Header{},
		Body:      &Body{},
	}
}

// WithAction sets the WS-Addressing Action header.
func (e *Envelope) WithAction(action string) *Envelope {
	e.Header.Action = action
	return e
}

// WithTo sets the WS-Addressing To header (the endpoint URL).
func (e *Envelope) WithTo(to string) *Envelope {
	e.Header.To = to
	return e
}

// WithMessageID sets the WS-Addressing MessageID header.
func (e *Envelope) WithMessageID(messageID string) *Envelope {
	e.Header.MessageID = messageID
	return e
}

// WithReplyTo sets the WS-Addressing ReplyTo header.
func (e *Envelope) WithReplyTo(address string) *Envelope {
	e.Header.ReplyTo = &ReplyTo{Address: address}
	return e
}

// WithResourceURI sets the WS-Management ResourceURI header.
func (e *Envelope) WithResourceURI(uri string) *Envelope {
	e.Header.ResourceURI = uri
	return e
}

// WithMaxEnvelopeSize sets the WS-Management MaxEnvelopeSize header.
func (e *Envelope) WithMaxEnvelopeSize(size int) *Envelope {
	e.Header.MaxEnvelopeSize = size
	return e
}

// WithOperationTimeout sets the WS-Management OperationTimeout header.
// The timeout should be in ISO 8601 duration format (e.g., "PT60S" for 60 seconds).
func (e *Envelope) WithOperationTimeout(timeout string) *Envelope {
	e.Header.OperationTimeout = timeout
	return e
}

// WithShellNamespace adds the Windows Shell namespace to the envelope.
func (e *Envelope) WithShellNamespace() *Envelope {
	e.NsShellNs = NsShell
	return e
}

// WithSelector adds a selector to the SelectorSet.
func (e *Envelope) WithSelector(name, value string) *Envelope {
	if e.Header.SelectorSet == nil {
		e.Header.SelectorSet = &SelectorSet{}
	}
	e.Header.SelectorSet.Selectors = append(e.Header.SelectorSet.Selectors,
		Selector{Name: name, Value: value})
	return e
}

// WithOption adds an option to the OptionSet.
func (e *Envelope) WithOption(name, value string) *Envelope {
	if e.Header.OptionSet == nil {
		e.Header.OptionSet = &OptionSet{}
	}
	e.Header.OptionSet.Options = append(e.Header.OptionSet.Options,
		Option{Name: name, Value: value})
	return e
}

// WithBody sets the SOAP body content.
func (e *Envelope) WithBody(content []byte) *Envelope {
	e.Body.Content = content
	return e
}

// Marshal serializes the envelope to XML.
func (e *Envelope) Marshal() ([]byte, error) {
	return xml.Marshal(e)
}

// MarshalIndent serializes the envelope to indented XML.
func (e *Envelope) MarshalIndent(prefix, indent string) ([]byte, error) {
	return xml.MarshalIndent(e, prefix, indent)
}
