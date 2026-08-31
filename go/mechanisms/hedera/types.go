package hedera

import (
	"context"

	"github.com/x402-foundation/x402/go/v2/types"
)

// ExactHederaPayload is the V2 payment payload body for Hedera exact.
type ExactHederaPayload struct {
	Transaction string `json:"transaction"` // Base64 encoded TransferTransaction
}

// TransferEntry is a single signed transfer (positive credit, negative debit).
type TransferEntry struct {
	AccountID string
	Amount    string
}

// DebitedPayer is a net-debiting account inferred from transfer lists.
type DebitedPayer struct {
	AccountID string
	Amount    string // absolute (positive) debit amount
}

// InspectedTransaction is a normalized TransferTransaction for verification.
type InspectedTransaction struct {
	TransactionType      string
	TransactionID        string
	TransactionIDAccount string
	HasNonTransferOps    bool
	HbarTransfers        []TransferEntry
	TokenTransfers       map[string][]TransferEntry
}

// SignatureCheck is the result of verifyPayerSignature / preflightTransfer.
type SignatureCheck struct {
	OK      bool
	Reason  string
	Message string
}

// AccountResolution is the result of optional ResolveAccount.
type AccountResolution struct {
	Exists  bool
	IsAlias bool
}

// TransactionSubmittedError reports a failed or unknown outcome after node acceptance.
type TransactionSubmittedError struct {
	TransactionID string
	Err           error
}

func (e *TransactionSubmittedError) Error() string {
	if e == nil || e.Err == nil {
		return "transaction submitted without a confirmed successful outcome"
	}
	return e.Err.Error()
}

func (e *TransactionSubmittedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ClientHederaSigner creates partially signed transfer transactions.
type ClientHederaSigner interface {
	// AccountID returns the payer account id.
	AccountID() string

	// CreatePartiallySignedTransferTransaction builds and payer-signs a transfer.
	CreatePartiallySignedTransferTransaction(ctx context.Context, requirements types.PaymentRequirements) (string, error)
}

// FacilitatorHederaSigner is the facilitator fee-payer interface (mirrors TS).
type FacilitatorHederaSigner interface {
	// GetAddresses returns managed fee-payer account ids for the network.
	GetAddresses(ctx context.Context, network string) []string

	// SignAndSubmitTransaction co-signs as feePayer and submits; must wait for SUCCESS.
	SignAndSubmitTransaction(ctx context.Context, transactionBase64, feePayer, network string) (txID string, err error)

	// VerifyPayerSignature checks the payer signed the frozen transaction body
	// (default impl reads the account key from Mirror Node; no operator query).
	VerifyPayerSignature(ctx context.Context, payer, transactionBase64, network string) SignatureCheck

	// PreflightTransfer fail-closed balance / association checks.
	PreflightTransfer(ctx context.Context, payer, payTo, asset, amount, network string) SignatureCheck

	// ResolveAccount optionally resolves payTo for alias policy (may be nil-capable via type assert).
	ResolveAccount(ctx context.Context, accountIDOrAlias, network string) (AccountResolution, error)
}

// DefaultAssetConfig is used by the server money parser fallback.
type DefaultAssetConfig struct {
	Asset    string
	Decimals int
}

// AssetInfo describes a Hedera fungible token.
type AssetInfo struct {
	Address  string
	Symbol   string
	Decimals int
}

// NetworkConfig contains network-specific defaults.
type NetworkConfig struct {
	Name         string
	CAIP2        string
	MirrorURL    string
	DefaultAsset AssetInfo
}

// ClientConfig contains optional client configuration.
type ClientConfig struct {
	MirrorNodeURL string
	NodeURL       string // optional custom consensus node (unused by default helpers)
}

// ServerConfig contains optional server configuration.
type ServerConfig struct {
	DefaultAssets map[string]DefaultAssetConfig
}

// FacilitatorConfig contains optional facilitator scheme configuration.
type FacilitatorConfig struct {
	AliasPolicy string // reject (default) or allow
}

// OperatorCredentials is one fee-payer account + private key for the default signer.
type OperatorCredentials struct {
	AccountID  string
	PrivateKey string // ECDSA hex (0x-optional), ED25519 hex/DER, or hiero FromString formats
}

// SignerConfig configures the default FacilitatorHederaSigner implementation.
type SignerConfig struct {
	Operators     []OperatorCredentials
	MirrorNodeURL string // optional override; empty uses network default
}

var (
	// NetworkConfigs maps CAIP-2 identifiers to network configurations.
	NetworkConfigs = map[string]NetworkConfig{
		HederaMainnetCAIP2: {
			Name:      "Hedera Mainnet",
			CAIP2:     HederaMainnetCAIP2,
			MirrorURL: HederaMainnetMirrorNodeURL,
			DefaultAsset: AssetInfo{
				Address:  HederaMainnetUSDC,
				Symbol:   "USDC",
				Decimals: HederaUSDCDecimals,
			},
		},
		HederaTestnetCAIP2: {
			Name:      "Hedera Testnet",
			CAIP2:     HederaTestnetCAIP2,
			MirrorURL: HederaTestnetMirrorNodeURL,
			DefaultAsset: AssetInfo{
				Address:  HederaTestnetUSDC,
				Symbol:   "USDC",
				Decimals: HederaUSDCDecimals,
			},
		},
	}
)
