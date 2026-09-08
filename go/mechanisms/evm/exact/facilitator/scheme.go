package facilitator

import (
	"context"
	"fmt"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

// ExactEvmSchemeConfig holds configuration for the ExactEvmScheme facilitator
type ExactEvmSchemeConfig struct {
	// EIP6492AllowedFactories is the allowlist of factory contract addresses (hex strings,
	// case-insensitive) that the facilitator will call when deploying an undeployed smart wallet
	// via ERC-6492. A non-empty list enables ERC-4337 smart wallet deployment. An empty list
	// (the default) denies all factory deployment calls. Facilitators must explicitly list every
	// factory they trust to prevent arbitrary transaction injection via attacker-controlled
	// ERC-6492 signature wrappers.
	EIP6492AllowedFactories []string
	// SimulateInSettle reruns transfer simulation during settle. Verify always simulates.
	SimulateInSettle bool
	// ERC7710GasLimit is the explicit simulation and transaction gas limit.
	// ERC-7710 is disabled when this is zero.
	ERC7710GasLimit uint64
}

// ExactEvmScheme implements the SchemeNetworkFacilitator interface for EVM exact payments (V2)
type ExactEvmScheme struct {
	signer       evm.FacilitatorEvmSigner
	config       ExactEvmSchemeConfig
	pendingStore x402.PendingSettlementStore
}

// NewExactEvmScheme creates a new ExactEvmScheme
// Args:
//
//	signer: The EVM signer for facilitator operations
//	config: Optional configuration (nil uses defaults)
//
// Returns:
//
//	Configured ExactEvmScheme instance
func NewExactEvmScheme(signer evm.FacilitatorEvmSigner, config *ExactEvmSchemeConfig) *ExactEvmScheme {
	cfg := ExactEvmSchemeConfig{}
	if config != nil {
		cfg = *config
	}
	return &ExactEvmScheme{
		signer:       signer,
		config:       cfg,
		pendingStore: x402.NewInMemoryPendingSettlementStore(),
	}
}

// SetPendingSettlementStore overrides the default in-memory
// PendingSettlementStore. Used by multi-instance facilitators (e.g.
// cdp-facilitator) to inject a shared, network-backed implementation (e.g.
// Redis) so a settle retry landing on a different replica still reconciles
// against the transaction the first replica broadcast. A nil store is a
// no-op.
func (f *ExactEvmScheme) SetPendingSettlementStore(store x402.PendingSettlementStore) {
	if store != nil {
		f.pendingStore = store
	}
}

// Scheme returns the scheme identifier
func (f *ExactEvmScheme) Scheme() string {
	return evm.SchemeExact
}

// CaipFamily returns the CAIP family pattern this facilitator supports
func (f *ExactEvmScheme) CaipFamily() string {
	return "eip155:*"
}

// GetExtra returns mechanism-specific extra data for the supported kinds endpoint.
// For EVM, no extra data is needed.
func (f *ExactEvmScheme) GetExtra(_ x402.Network) map[string]interface{} {
	return nil
}

// GetSigners returns signer addresses used by this facilitator.
// Returns all addresses this facilitator can use for signing/settling transactions.
func (f *ExactEvmScheme) GetSigners(_ x402.Network) []string {
	return f.signer.GetAddresses()
}

// Verify verifies a V2 payment payload against requirements.
// Routes to ERC-7710, Permit2, or EIP-3009 verification.
func (f *ExactEvmScheme) Verify(
	ctx context.Context,
	payload types.PaymentPayload,
	requirements types.PaymentRequirements,
	fctx *x402.FacilitatorContext,
) (*x402.VerifyResponse, error) {
	if evm.HasERC7710PayloadFields(payload.Payload) || requestsERC7710(payload.Accepted, requirements) {
		erc7710Payload, err := evm.ERC7710PayloadFromMap(payload.Payload)
		if err != nil {
			return nil, x402.NewVerifyError(ErrInvalidPayload, "", fmt.Sprintf("failed to parse ERC-7710 payload: %s", err.Error()))
		}
		return f.verifyERC7710(ctx, payload, requirements, erc7710Payload, fctx, true)
	}

	isPermit2 := evm.IsPermit2Payload(payload.Payload)

	if isPermit2 {
		permit2Payload, err := evm.Permit2PayloadFromMap(payload.Payload)
		if err != nil {
			return nil, x402.NewVerifyError(ErrInvalidPayload, "", fmt.Sprintf("failed to parse Permit2 payload: %s", err.Error()))
		}
		return VerifyPermit2(ctx, f.signer, payload, requirements, permit2Payload, fctx, nil)
	}

	return f.verifyEIP3009(ctx, payload, requirements, true)
}

// Settle settles a V2 payment on-chain.
// Routes to ERC-7710, Permit2, or EIP-3009 settlement.
func (f *ExactEvmScheme) Settle(
	ctx context.Context,
	payload types.PaymentPayload,
	requirements types.PaymentRequirements,
	fctx *x402.FacilitatorContext,
) (*x402.SettleResponse, error) {
	if evm.HasERC7710PayloadFields(payload.Payload) || requestsERC7710(payload.Accepted, requirements) {
		erc7710Payload, err := evm.ERC7710PayloadFromMap(payload.Payload)
		if err != nil {
			network := x402.Network(payload.Accepted.Network)
			return nil, x402.NewSettleError(ErrInvalidPayload, "", network, "", fmt.Sprintf("failed to parse ERC-7710 payload: %s", err.Error()))
		}
		return f.settleERC7710(ctx, payload, requirements, erc7710Payload, fctx)
	}

	isPermit2 := evm.IsPermit2Payload(payload.Payload)

	if isPermit2 {
		permit2Payload, err := evm.Permit2PayloadFromMap(payload.Payload)
		if err != nil {
			network := x402.Network(payload.Accepted.Network)
			return nil, x402.NewSettleError(ErrInvalidPayload, "", network, "", fmt.Sprintf("failed to parse Permit2 payload: %s", err.Error()))
		}
		return SettlePermit2(ctx, f.signer, payload, requirements, permit2Payload, fctx, &Permit2FacilitatorConfig{
			SimulateInSettle:       f.config.SimulateInSettle,
			PendingSettlementStore: f.pendingStore,
		})
	}

	return f.settleEIP3009(ctx, payload, requirements, fctx)
}

func requestsERC7710(accepted, requirements types.PaymentRequirements) bool {
	return assetTransferMethod(accepted) == evm.AssetTransferMethodERC7710 ||
		assetTransferMethod(requirements) == evm.AssetTransferMethodERC7710
}

func assetTransferMethod(requirements types.PaymentRequirements) evm.AssetTransferMethod {
	if requirements.Extra == nil {
		return evm.AssetTransferMethodEIP3009
	}
	method, ok := requirements.Extra["assetTransferMethod"].(string)
	if !ok {
		return evm.AssetTransferMethodEIP3009
	}
	return evm.AssetTransferMethod(method)
}
