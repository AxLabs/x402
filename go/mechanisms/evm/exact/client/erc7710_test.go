package client

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

type erc7710ProviderStub struct {
	payload      *evm.ExactERC7710Payload
	err          error
	requirements types.PaymentRequirements
}

func (p *erc7710ProviderStub) CreateERC7710Payload(
	_ context.Context,
	requirements types.PaymentRequirements,
) (*evm.ExactERC7710Payload, error) {
	p.requirements = requirements
	return p.payload, p.err
}

func erc7710ClientRequirements() types.PaymentRequirements {
	return types.PaymentRequirements{
		Scheme:  evm.SchemeExact,
		Network: "eip155:84532",
		Asset:   "0x1111111111111111111111111111111111111111",
		Amount:  "10000",
		PayTo:   "0x2222222222222222222222222222222222222222",
		Extra: map[string]interface{}{
			"assetTransferMethod": string(evm.AssetTransferMethodERC7710),
		},
	}
}

func TestCreatePaymentPayloadERC7710UsesProvider(t *testing.T) {
	provider := &erc7710ProviderStub{payload: &evm.ExactERC7710Payload{
		DelegationManager: "0x3333333333333333333333333333333333333333",
		PermissionContext: "0x1234",
		Delegator:         "0x4444444444444444444444444444444444444444",
	}}
	signer := &rpcTestSigner{}
	scheme := NewExactEvmScheme(signer, nil).SetERC7710PayloadProvider(provider)
	requirements := erc7710ClientRequirements()

	payload, err := scheme.CreatePaymentPayload(context.Background(), requirements)
	if err != nil {
		t.Fatalf("CreatePaymentPayload failed: %v", err)
	}
	if !evm.IsERC7710Payload(payload.Payload) {
		t.Fatalf("unexpected payload: %#v", payload.Payload)
	}
	if provider.requirements.Network != requirements.Network {
		t.Fatal("provider did not receive payment requirements")
	}
	if signer.typedDataCalls != 0 {
		t.Fatal("ERC-7710 must not use the typed-data signer")
	}
}

func TestCreatePaymentPayloadERC7710WithoutProviderIsUnsupported(t *testing.T) {
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil)

	_, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements())
	if err == nil || !strings.Contains(err.Error(), ErrERC7710Unsupported) {
		t.Fatalf("expected explicit unsupported error, got %v", err)
	}
}

func TestCreatePaymentPayloadERC7710RejectsProviderFailure(t *testing.T) {
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(
		&erc7710ProviderStub{err: errors.New("session expired")},
	)

	_, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements())
	if err == nil || !strings.Contains(err.Error(), ErrERC7710PayloadProviderFailed) {
		t.Fatalf("expected provider error, got %v", err)
	}
}
