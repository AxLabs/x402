package client

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

// ERC7710PayloadProvider supplies delegation data created outside the x402
// typed-data signer, such as by a wallet or session-delegation system.
type ERC7710PayloadProvider interface {
	CreateERC7710Payload(ctx context.Context, requirements types.PaymentRequirements) (*evm.ExactERC7710Payload, error)
}

func (c *ExactEvmScheme) createERC7710Payload(
	ctx context.Context,
	requirements types.PaymentRequirements,
) (types.PaymentPayload, error) {
	if c.erc7710PayloadProvider == nil {
		return types.PaymentPayload{}, errors.New(ErrERC7710Unsupported)
	}
	if requirements.Scheme != evm.SchemeExact {
		return types.PaymentPayload{}, fmt.Errorf("%s: invalid scheme %q", ErrERC7710InvalidRequirements, requirements.Scheme)
	}
	chainID, err := evm.GetEvmChainId(string(requirements.Network))
	if err != nil {
		return types.PaymentPayload{}, fmt.Errorf("%s: %w", ErrERC7710InvalidRequirements, err)
	}
	if chainID.Sign() <= 0 {
		return types.PaymentPayload{}, fmt.Errorf("%s: chain ID must be positive", ErrERC7710InvalidRequirements)
	}
	if !evm.IsValidNonZeroAddress(requirements.Asset) {
		return types.PaymentPayload{}, fmt.Errorf("%s: invalid asset", ErrERC7710InvalidRequirements)
	}
	if !evm.IsValidNonZeroAddress(requirements.PayTo) {
		return types.PaymentPayload{}, fmt.Errorf("%s: invalid payTo", ErrERC7710InvalidRequirements)
	}
	amount, ok := new(big.Int).SetString(requirements.Amount, 10)
	if !ok || amount.Sign() <= 0 || amount.BitLen() > 256 {
		return types.PaymentPayload{}, fmt.Errorf("%s: invalid amount", ErrERC7710InvalidRequirements)
	}

	provided, err := c.erc7710PayloadProvider.CreateERC7710Payload(ctx, requirements)
	if err != nil {
		return types.PaymentPayload{}, fmt.Errorf("%s: %w", ErrERC7710PayloadProviderFailed, err)
	}
	if provided == nil {
		return types.PaymentPayload{}, fmt.Errorf("%s: provider returned nil payload", ErrERC7710PayloadProviderFailed)
	}
	parsed, err := evm.ERC7710PayloadFromMap(provided.ToMap())
	if err != nil {
		return types.PaymentPayload{}, fmt.Errorf("%s: %w", ErrERC7710PayloadProviderFailed, err)
	}

	return types.PaymentPayload{
		X402Version: 2,
		Payload:     parsed.ToMap(),
	}, nil
}
