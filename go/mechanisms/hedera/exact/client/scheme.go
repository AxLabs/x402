package client

import (
	"context"
	"fmt"

	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera"
	"github.com/x402-foundation/x402/go/v2/types"
)

const (
	ErrUnsupportedScheme = "unsupported_scheme"
	ErrMissingFeePayer   = "missing_fee_payer"
)

// ExactHederaScheme implements SchemeNetworkClient for Hedera exact (V2).
type ExactHederaScheme struct {
	signer hedera.ClientHederaSigner
}

// NewExactHederaScheme creates a client-side Hedera exact scheme.
func NewExactHederaScheme(signer hedera.ClientHederaSigner) *ExactHederaScheme {
	return &ExactHederaScheme{signer: signer}
}

func (c *ExactHederaScheme) Scheme() string { return hedera.SchemeExact }

func (c *ExactHederaScheme) CreatePaymentPayload(
	ctx context.Context,
	requirements types.PaymentRequirements,
) (types.PaymentPayload, error) {
	if requirements.Scheme != hedera.SchemeExact {
		return types.PaymentPayload{}, fmt.Errorf("%s: %s", ErrUnsupportedScheme, requirements.Scheme)
	}
	if err := hedera.AssertSupportedNetwork(string(requirements.Network)); err != nil {
		return types.PaymentPayload{}, err
	}
	if requirements.Extra == nil {
		return types.PaymentPayload{}, fmt.Errorf("%s: feePayer is required in paymentRequirements.extra", ErrMissingFeePayer)
	}
	if _, ok := requirements.Extra["feePayer"].(string); !ok {
		return types.PaymentPayload{}, fmt.Errorf("%s: feePayer is required in paymentRequirements.extra", ErrMissingFeePayer)
	}

	txB64, err := c.signer.CreatePartiallySignedTransferTransaction(ctx, requirements)
	if err != nil {
		return types.PaymentPayload{}, err
	}

	return types.PaymentPayload{
		X402Version: 2,
		Payload: map[string]interface{}{
			"transaction": txB64,
		},
		Accepted: requirements,
	}, nil
}
