package client

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/extensions/paymentidentifier"

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

	payload, err := scheme.CreatePaymentPayload(context.Background(), requirements, x402.PaymentPayloadContext{})
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

	_, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements(), x402.PaymentPayloadContext{})
	if err == nil || !strings.Contains(err.Error(), ErrERC7710Unsupported) {
		t.Fatalf("expected explicit unsupported error, got %v", err)
	}
}

func TestCreatePaymentPayloadERC7710RejectsProviderFailure(t *testing.T) {
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(
		&erc7710ProviderStub{err: errors.New("session expired")},
	)

	_, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements(), x402.PaymentPayloadContext{})
	if err == nil || !strings.Contains(err.Error(), ErrERC7710PayloadProviderFailed) {
		t.Fatalf("expected provider error, got %v", err)
	}
}

func TestCreatePaymentPayloadERC7710RejectsInvalidRequirements(t *testing.T) {
	validProvider := &erc7710ProviderStub{payload: &evm.ExactERC7710Payload{
		DelegationManager: "0x3333333333333333333333333333333333333333",
		PermissionContext: "0x1234",
		Delegator:         "0x4444444444444444444444444444444444444444",
	}}
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(validProvider)
	overflowAmount := new(big.Int).Lsh(big.NewInt(1), 256).String()

	tests := map[string]types.PaymentRequirements{
		"wrong scheme": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Scheme = evm.SchemeUpto
			return req
		}(),
		"invalid network": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Network = "not-a-caip"
			return req
		}(),
		"zero asset": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Asset = "0x" + strings.Repeat("0", 40)
			return req
		}(),
		"zero payTo": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.PayTo = "0x" + strings.Repeat("0", 40)
			return req
		}(),
		"zero amount": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Amount = "0"
			return req
		}(),
		"overflow amount": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Amount = overflowAmount
			return req
		}(),
		"non-numeric amount": func() types.PaymentRequirements {
			req := erc7710ClientRequirements()
			req.Amount = "1.5"
			return req
		}(),
	}

	for name, requirements := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := scheme.CreatePaymentPayload(context.Background(), requirements, x402.PaymentPayloadContext{})
			if err == nil || !strings.Contains(err.Error(), ErrERC7710InvalidRequirements) {
				t.Fatalf("expected invalid requirements, got %v", err)
			}
		})
	}
}

func TestCreatePaymentPayloadERC7710RejectsNilAndMalformedProviderPayload(t *testing.T) {
	requirements := erc7710ClientRequirements()

	_, err := NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(
		&erc7710ProviderStub{},
	).CreatePaymentPayload(context.Background(), requirements, x402.PaymentPayloadContext{})
	if err == nil || !strings.Contains(err.Error(), ErrERC7710PayloadProviderFailed) {
		t.Fatalf("expected nil payload error, got %v", err)
	}

	_, err = NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(
		&erc7710ProviderStub{payload: &evm.ExactERC7710Payload{
			DelegationManager: "0x" + strings.Repeat("0", 40),
			PermissionContext: "0x1234",
			Delegator:         "0x4444444444444444444444444444444444444444",
		}},
	).CreatePaymentPayload(context.Background(), requirements, x402.PaymentPayloadContext{})
	if err == nil || !strings.Contains(err.Error(), ErrERC7710PayloadProviderFailed) {
		t.Fatalf("expected malformed payload error, got %v", err)
	}
}

func TestCreatePaymentPayloadWithExtensionsERC7710DoesNotSignTypedData(t *testing.T) {
	signer := &rpcTestSigner{}
	scheme := NewExactEvmScheme(signer, nil).SetERC7710PayloadProvider(&erc7710ProviderStub{
		payload: &evm.ExactERC7710Payload{
			DelegationManager: "0x3333333333333333333333333333333333333333",
			PermissionContext: "0xabcd",
			Delegator:         "0x4444444444444444444444444444444444444444",
		},
	})

	payload, err := scheme.CreatePaymentPayload(
		context.Background(),
		erc7710ClientRequirements(),
		x402.PaymentPayloadContext{Extensions: map[string]interface{}{"eip2612GasSponsoring": map[string]interface{}{}}},
	)
	if err != nil {
		t.Fatalf("CreatePaymentPayload failed: %v", err)
	}
	if !evm.IsERC7710Payload(payload.Payload) {
		t.Fatalf("unexpected payload: %#v", payload.Payload)
	}
	if len(payload.Extensions) != 1 || payload.Extensions["payment-identifier"] == nil {
		t.Fatal("ERC-7710 must attach only a payment identifier")
	}
	if signer.typedDataCalls != 0 {
		t.Fatal("ERC-7710 must not use the typed-data signer")
	}
}

func TestCreatePaymentPayloadRejectsUnknownAssetTransferMethod(t *testing.T) {
	requirements := erc7710ClientRequirements()
	requirements.Extra = map[string]interface{}{"assetTransferMethod": "not-a-method"}

	_, err := NewExactEvmScheme(&rpcTestSigner{}, nil).CreatePaymentPayload(context.Background(), requirements, x402.PaymentPayloadContext{})
	if err == nil || !strings.Contains(err.Error(), ErrUnsupportedAssetTransferMethod) {
		t.Fatalf("expected unsupported method, got %v", err)
	}
}

func TestCreatePaymentPayloadDefaultAndPermit2AreNotERC7710(t *testing.T) {
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil)
	base := types.PaymentRequirements{
		Scheme:            evm.SchemeExact,
		Network:           "eip155:84532",
		Asset:             "0x1111111111111111111111111111111111111111",
		Amount:            "10000",
		PayTo:             "0x2222222222222222222222222222222222222222",
		MaxTimeoutSeconds: 60,
	}

	defaultPayload, err := scheme.CreatePaymentPayload(context.Background(), base, x402.PaymentPayloadContext{})
	if err != nil {
		t.Fatalf("default payload: %v", err)
	}
	if !evm.IsEIP3009Payload(defaultPayload.Payload) || evm.HasERC7710PayloadFields(defaultPayload.Payload) {
		t.Fatalf("default route must stay EIP-3009: %#v", defaultPayload.Payload)
	}

	permit2Req := base
	permit2Req.Extra = map[string]interface{}{"assetTransferMethod": string(evm.AssetTransferMethodPermit2)}
	permit2Payload, err := scheme.CreatePaymentPayload(context.Background(), permit2Req, x402.PaymentPayloadContext{})
	if err != nil {
		t.Fatalf("permit2 payload: %v", err)
	}
	if !evm.IsPermit2Payload(permit2Payload.Payload) || evm.HasERC7710PayloadFields(permit2Payload.Payload) {
		t.Fatalf("permit2 route must stay Permit2: %#v", permit2Payload.Payload)
	}
}

func TestERC7710ClientPaymentIdentity(t *testing.T) {
	scheme := NewExactEvmScheme(&rpcTestSigner{}, nil).SetERC7710PayloadProvider(&erc7710ProviderStub{payload: &evm.ExactERC7710Payload{
		DelegationManager: "0x3333333333333333333333333333333333333333", PermissionContext: "0x1234", Delegator: "0x4444444444444444444444444444444444444444",
	}})
	first, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements(), x402.PaymentPayloadContext{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements(), x402.PaymentPayloadContext{})
	if err != nil {
		t.Fatal(err)
	}
	firstID, _ := paymentidentifier.ExtractPaymentIdentifier(first, true)
	secondID, _ := paymentidentifier.ExtractPaymentIdentifier(second, true)
	if firstID == "" || secondID == "" || firstID == secondID {
		t.Fatal("distinct purchases require distinct payment IDs")
	}
	retry, err := scheme.CreatePaymentPayload(context.Background(), erc7710ClientRequirements(), x402.PaymentPayloadContext{Extensions: first.Extensions})
	if err != nil {
		t.Fatal(err)
	}
	retryID, _ := paymentidentifier.ExtractPaymentIdentifier(retry, true)
	if retryID != firstID {
		t.Fatal("explicit retry ID changed")
	}
}
