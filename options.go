package wkwcrypt

// Encoding selects the text representation used for newly encrypted values.
type Encoding string

const (
	// EncodingWords encodes the envelope with the frozen BIP-0039 English dictionary.
	EncodingWords Encoding = "words"
	// EncodingBase64 encodes the binary envelope with unpadded URL-safe Base64.
	EncodingBase64 Encoding = "b64"
)

// Option configures encryption or decryption. WithEncoding affects encryption only.
type Option func(*options)

type options struct {
	encoding Encoding
	aad      []byte
}

func defaultOptions() options {
	return options{encoding: EncodingBase64}
}

// WithEncoding selects the representation for a newly encrypted value.
func WithEncoding(encoding Encoding) Option {
	return func(opts *options) {
		opts.encoding = encoding
	}
}

// WithAAD binds contextual data to a ciphertext without encrypting it.
func WithAAD(aad []byte) Option {
	return func(opts *options) {
		opts.aad = aad
	}
}

func applyOptions(opts []Option) options {
	configured := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&configured)
		}
	}
	return configured
}
