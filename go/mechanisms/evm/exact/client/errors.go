package client

// Client error constants for the exact EVM scheme (V2)
const (
	ErrInvalidAmount                    = "invalid_exact_evm_client_amount"
	ErrFailedToSignAuthorization        = "invalid_exact_evm_client_failed_to_sign_authorization"
	ErrFailedToSignPermit2Authorization = "invalid_exact_evm_client_failed_to_sign_permit2_authorization"
	ErrUnsupportedAssetTransferMethod   = "unsupported_exact_evm_asset_transfer_method"
	ErrERC7710Unsupported               = "unsupported_exact_evm_erc7710_payload_provider"
	ErrERC7710InvalidRequirements       = "invalid_exact_evm_erc7710_requirements"
	ErrERC7710PayloadProviderFailed     = "invalid_exact_evm_erc7710_payload_provider"
)
