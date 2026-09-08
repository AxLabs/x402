package facilitator

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

var erc7579SingleExecutionMode [32]byte

// BuildERC7710RedeemCalldata builds redeemDelegations calldata containing one
// ERC-7579 single execution of ERC20.transfer(payTo, amount).
func BuildERC7710RedeemCalldata(
	erc7710Payload *evm.ExactERC7710Payload,
	requirements types.PaymentRequirements,
) ([]byte, error) {
	if erc7710Payload == nil {
		return nil, fmt.Errorf("nil ERC-7710 payload")
	}
	amount, ok := new(big.Int).SetString(requirements.Amount, 10)
	if !ok || amount.Sign() <= 0 || amount.BitLen() > 256 {
		return nil, fmt.Errorf("invalid amount")
	}
	if !evm.IsValidNonZeroAddress(requirements.Asset) || !evm.IsValidNonZeroAddress(requirements.PayTo) {
		return nil, fmt.Errorf("invalid payment address")
	}
	permissionContext, err := evm.HexToBytes(erc7710Payload.PermissionContext)
	if err != nil || len(permissionContext) == 0 {
		return nil, fmt.Errorf("invalid permissionContext")
	}

	erc20ABI, err := abi.JSON(strings.NewReader(string(evm.ERC20TransferABI)))
	if err != nil {
		return nil, fmt.Errorf("parse ERC20 ABI: %w", err)
	}
	transferCalldata, err := erc20ABI.Pack(
		evm.FunctionERC20Transfer,
		common.HexToAddress(requirements.PayTo),
		amount,
	)
	if err != nil {
		return nil, fmt.Errorf("encode ERC20 transfer: %w", err)
	}

	executionCalldata := make([]byte, 0, common.AddressLength+32+len(transferCalldata))
	executionCalldata = append(executionCalldata, common.HexToAddress(requirements.Asset).Bytes()...)
	executionCalldata = append(executionCalldata, make([]byte, 32)...)
	executionCalldata = append(executionCalldata, transferCalldata...)

	managerABI, err := abi.JSON(strings.NewReader(string(evm.ERC7710RedeemDelegationsABI)))
	if err != nil {
		return nil, fmt.Errorf("parse ERC-7710 ABI: %w", err)
	}
	calldata, err := managerABI.Pack(
		evm.FunctionRedeemDelegations,
		[][]byte{permissionContext},
		[][32]byte{erc7579SingleExecutionMode},
		[][]byte{executionCalldata},
	)
	if err != nil {
		return nil, fmt.Errorf("encode redeemDelegations: %w", err)
	}
	return calldata, nil
}

func (f *ExactEvmScheme) verifyERC7710(
	ctx context.Context,
	payload types.PaymentPayload,
	requirements types.PaymentRequirements,
	erc7710Payload *evm.ExactERC7710Payload,
	fctx *x402.FacilitatorContext,
	simulate bool,
) (*x402.VerifyResponse, error) {
	payer := erc7710Payload.Delegator
	if payload.Accepted.Scheme != evm.SchemeExact || requirements.Scheme != evm.SchemeExact {
		return nil, x402.NewVerifyError(ErrInvalidScheme, payer, "scheme mismatch")
	}
	if payload.Accepted.Network != requirements.Network {
		return nil, x402.NewVerifyError(ErrNetworkMismatch, payer, "network mismatch")
	}
	requiredChainID, err := evm.GetEvmChainId(string(requirements.Network))
	if err != nil || requiredChainID.Sign() <= 0 {
		if err == nil {
			err = fmt.Errorf("chain ID must be positive")
		}
		return nil, x402.NewVerifyError(ErrFailedToGetNetworkConfig, payer, err.Error())
	}
	signerChainID, err := f.signer.GetChainID(ctx)
	if err != nil {
		return nil, x402.NewVerifyError(ErrFailedToGetNetworkConfig, payer, err.Error())
	}
	if signerChainID == nil || signerChainID.Cmp(requiredChainID) != 0 {
		return nil, x402.NewVerifyError(ErrNetworkMismatch, payer, "signer network does not match requirements")
	}
	if method, ok := strictAssetTransferMethod(payload.Accepted); !ok || method != evm.AssetTransferMethodERC7710 {
		return nil, x402.NewVerifyError(ErrERC7710InvalidMethod, payer, "accepted assetTransferMethod must be erc7710")
	}
	if method, ok := strictAssetTransferMethod(requirements); !ok || method != evm.AssetTransferMethodERC7710 {
		return nil, x402.NewVerifyError(ErrERC7710InvalidMethod, payer, "requirements assetTransferMethod must be erc7710")
	}
	if !evm.IsValidNonZeroAddress(payload.Accepted.Asset) ||
		!evm.IsValidNonZeroAddress(payload.Accepted.PayTo) ||
		!evm.IsValidNonZeroAddress(requirements.Asset) ||
		!evm.IsValidNonZeroAddress(requirements.PayTo) {
		return nil, x402.NewVerifyError(ErrERC7710InvalidAddress, payer, "invalid asset or payTo address")
	}
	if !strings.EqualFold(payload.Accepted.Asset, requirements.Asset) ||
		!strings.EqualFold(payload.Accepted.PayTo, requirements.PayTo) {
		return nil, x402.NewVerifyError(ErrERC7710AcceptedMismatch, payer, "accepted asset or payTo mismatch")
	}
	acceptedAmount, acceptedOK := parseERC7710Amount(payload.Accepted.Amount)
	requiredAmount, requiredOK := parseERC7710Amount(requirements.Amount)
	if !acceptedOK || !requiredOK {
		return nil, x402.NewVerifyError(ErrERC7710InvalidAmount, payer, "invalid amount")
	}
	if acceptedAmount.Cmp(requiredAmount) != 0 {
		return nil, x402.NewVerifyError(ErrERC7710AcceptedMismatch, payer, "accepted amount mismatch")
	}
	if f.config.ERC7710GasLimit == 0 {
		return nil, x402.NewVerifyError(ErrERC7710GasLimitRequired, payer, "ERC7710GasLimit must be configured")
	}
	if permissionContextMinimumGas(erc7710Payload.PermissionContext) > f.config.ERC7710GasLimit {
		return nil, x402.NewVerifyError(ErrERC7710CalldataExceedsGasLimit, payer, "permissionContext cannot fit within ERC7710GasLimit")
	}
	erc7710Signer, ok := f.signer.(evm.FacilitatorEvmSignerWithGasLimitedTransactions)
	if !ok {
		return nil, x402.NewVerifyError(ErrERC7710SignerUnsupported, payer, "signer lacks gas-limited simulation and transaction support")
	}
	caller, err := f.erc7710Caller()
	if err != nil {
		return nil, x402.NewVerifyError(ErrERC7710SignerUnsupported, payer, err.Error())
	}

	if reason, err := evm.ValidateAssetIsContract(ctx, f.signer, requirements.Asset); err != nil {
		return nil, fmt.Errorf("asset contract check failed: %w", err)
	} else if reason != "" {
		return nil, x402.NewVerifyError(reason, payer, "asset is not a deployed contract")
	}
	if err := requireDeployedContract(ctx, f.signer, erc7710Payload.DelegationManager, payer, ErrERC7710DelegationManagerNotFound); err != nil {
		return nil, err
	}
	if err := requireDeployedContract(ctx, f.signer, erc7710Payload.Delegator, payer, ErrERC7710DelegatorNotDeployed); err != nil {
		return nil, err
	}

	calldata, err := BuildERC7710RedeemCalldata(erc7710Payload, requirements)
	if err != nil {
		return nil, x402.NewVerifyError(ErrInvalidPayload, payer, err.Error())
	}
	dataSuffix, err := evm.ResolveDataSuffix(fctx, evm.DataSuffixContext{Payload: payload, Requirements: requirements})
	if err != nil {
		return nil, x402.NewVerifyError(ErrInvalidPayload, payer, err.Error())
	}
	calldata = append(calldata, dataSuffix...)
	if intrinsicCalldataGas(calldata) > f.config.ERC7710GasLimit {
		return nil, x402.NewVerifyError(ErrERC7710CalldataExceedsGasLimit, payer, "calldata intrinsic gas exceeds ERC7710GasLimit")
	}
	if simulate {
		if err := erc7710Signer.SimulateTransaction(
			ctx,
			caller,
			erc7710Payload.DelegationManager,
			calldata,
			f.config.ERC7710GasLimit,
		); err != nil {
			return nil, x402.NewVerifyError(ErrERC7710SimulationFailed, payer, evm.TruncateErrorMessage(err.Error()))
		}
	}

	return &x402.VerifyResponse{IsValid: true, Payer: payer}, nil
}

func (f *ExactEvmScheme) settleERC7710(
	ctx context.Context,
	payload types.PaymentPayload,
	requirements types.PaymentRequirements,
	erc7710Payload *evm.ExactERC7710Payload,
	fctx *x402.FacilitatorContext,
) (*x402.SettleResponse, error) {
	network := x402.Network(payload.Accepted.Network)
	payer := erc7710Payload.Delegator
	pendingKey := erc7710PendingKey(erc7710Payload, payload.Accepted, requirements)
	if txHash, ok, _ := f.pendingStore.Get(ctx, pendingKey); ok {
		_ = f.pendingStore.Delete(ctx, pendingKey)
		return awaitERC7710Settlement(ctx, f.pendingStore, f.signer, pendingKey, txHash, payer, network)
	}

	if _, err := f.verifyERC7710(ctx, payload, requirements, erc7710Payload, fctx, f.config.SimulateInSettle); err != nil {
		verifyErr := &x402.VerifyError{}
		if errors.As(err, &verifyErr) {
			return nil, x402.NewSettleError(verifyErr.InvalidReason, verifyErr.Payer, network, "", verifyErr.InvalidMessage)
		}
		return nil, x402.NewSettleError(ErrVerificationFailed, payer, network, "", err.Error())
	}

	calldata, err := BuildERC7710RedeemCalldata(erc7710Payload, requirements)
	if err != nil {
		return nil, x402.NewSettleError(ErrInvalidPayload, payer, network, "", err.Error())
	}
	dataSuffix, err := evm.ResolveDataSuffix(fctx, evm.DataSuffixContext{Payload: payload, Requirements: requirements})
	if err != nil {
		return nil, x402.NewSettleError(ErrInvalidPayload, payer, network, "", err.Error())
	}
	calldata = append(calldata, dataSuffix...)
	erc7710Signer := f.signer.(evm.FacilitatorEvmSignerWithGasLimitedTransactions)
	caller, err := f.erc7710Caller()
	if err != nil {
		return nil, x402.NewSettleError(ErrERC7710SignerUnsupported, payer, network, "", err.Error())
	}
	txHash, err := erc7710Signer.SendTransactionWithGasLimit(
		ctx,
		caller,
		erc7710Payload.DelegationManager,
		calldata,
		f.config.ERC7710GasLimit,
	)
	if err != nil {
		return nil, x402.NewSettleError(ErrERC7710SettlementFailed, payer, network, "", evm.TruncateErrorMessage(err.Error()))
	}
	return awaitERC7710Settlement(ctx, f.pendingStore, f.signer, pendingKey, txHash, payer, network)
}

func awaitERC7710Settlement(
	ctx context.Context,
	store x402.PendingSettlementStore,
	signer evm.FacilitatorEvmSigner,
	pendingKey string,
	txHash string,
	payer string,
	network x402.Network,
) (*x402.SettleResponse, error) {
	if _, err := evm.WaitForSettleReceiptWithPendingStore(
		ctx,
		store,
		pendingKey,
		signer,
		txHash,
		payer,
		network,
		ErrERC7710SettlementFailed,
		ErrERC7710SettlementFailed,
	); err != nil {
		return nil, err
	}
	return &x402.SettleResponse{Success: true, Transaction: txHash, Network: network, Payer: payer}, nil
}

func strictAssetTransferMethod(requirements types.PaymentRequirements) (evm.AssetTransferMethod, bool) {
	if requirements.Extra == nil {
		return "", false
	}
	method, ok := requirements.Extra["assetTransferMethod"].(string)
	return evm.AssetTransferMethod(method), ok
}

func parseERC7710Amount(value string) (*big.Int, bool) {
	amount, ok := new(big.Int).SetString(value, 10)
	return amount, ok && amount.Sign() > 0 && amount.BitLen() <= 256
}

func requireDeployedContract(
	ctx context.Context,
	signer evm.FacilitatorEvmSigner,
	address string,
	payer string,
	reason string,
) error {
	code, err := signer.GetCode(ctx, evm.NormalizeAddress(address))
	if err != nil {
		return fmt.Errorf("failed to check contract deployment: %w", err)
	}
	if len(code) == 0 {
		return x402.NewVerifyError(reason, payer, "address is not a deployed contract")
	}
	return nil
}

func (f *ExactEvmScheme) erc7710Caller() (string, error) {
	addresses := f.signer.GetAddresses()
	if len(addresses) == 0 || !evm.IsValidNonZeroAddress(addresses[0]) {
		return "", fmt.Errorf("signer returned no valid caller address")
	}
	return addresses[0], nil
}

func intrinsicCalldataGas(calldata []byte) uint64 {
	gas := uint64(21_000)
	for _, value := range calldata {
		if value == 0 {
			gas += 4
		} else {
			gas += 16
		}
	}
	return gas
}

func permissionContextMinimumGas(permissionContext string) uint64 {
	const transactionBaseGas = uint64(21_000)
	if len(permissionContext) < 2 {
		return transactionBaseGas
	}
	byteLength := uint64((len(permissionContext) - 2) / 2)
	if byteLength > (^uint64(0)-transactionBaseGas)/4 {
		return ^uint64(0)
	}
	return transactionBaseGas + byteLength*4
}

func erc7710PendingKey(
	erc7710Payload *evm.ExactERC7710Payload,
	accepted types.PaymentRequirements,
	requirements types.PaymentRequirements,
) string {
	parts := []string{
		strings.ToLower(erc7710Payload.DelegationManager),
		strings.ToLower(erc7710Payload.Delegator),
		erc7710Payload.PermissionContext,
		accepted.Scheme,
		accepted.Network,
		strings.ToLower(accepted.Asset),
		accepted.Amount,
		strings.ToLower(accepted.PayTo),
		string(assetTransferMethod(accepted)),
		requirements.Scheme,
		requirements.Network,
		strings.ToLower(requirements.Asset),
		requirements.Amount,
		strings.ToLower(requirements.PayTo),
		string(assetTransferMethod(requirements)),
	}
	return crypto.Keccak256Hash([]byte(strings.Join(parts, "\x00"))).Hex()
}
