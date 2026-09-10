package facilitator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	goethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/x402-foundation/x402/go/v2/extensions/paymentidentifier"

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
	if _, _, err := erc7710PaymentIdentity(payload, requirements, erc7710Payload); err != nil {
		return nil, x402.NewVerifyError(ErrInvalidPayload, payer, err.Error())
	}
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
	if !isERC7710ManagerAllowed(erc7710Payload.DelegationManager, f.config.ERC7710AllowedDelegationManagers) {
		return nil, x402.NewVerifyError(
			ErrERC7710DelegationManagerNotAllowed,
			payer,
			"delegation manager is not trusted by this facilitator",
		)
	}
	if !f.erc7710StoreConfigured && !f.config.ERC7710AllowInMemoryReplayStore {
		return nil, x402.NewVerifyError(
			ErrERC7710ReplayStoreRequired,
			payer,
			"durable ERC-7710 replay storage must be configured",
		)
	}
	if permissionContextMinimumGas(erc7710Payload.PermissionContext) > f.config.ERC7710GasLimit {
		return nil, x402.NewVerifyError(ErrERC7710CalldataExceedsGasLimit, payer, "permissionContext cannot fit within ERC7710GasLimit")
	}
	erc7710Signer, ok := f.signer.(evm.FacilitatorEvmSignerWithRecordedTransactions)
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
			if evm.IsDeterministicContractFailure(err) {
				return nil, x402.NewVerifyError(ErrERC7710SimulationFailed, payer, evm.TruncateErrorMessage(err.Error()))
			}
			return nil, fmt.Errorf("ERC-7710 simulation RPC failed: %w", err)
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
	settlementKey, fingerprint, err := erc7710PaymentIdentity(payload, requirements, erc7710Payload)
	if err != nil {
		return nil, x402.NewSettleError(ErrInvalidPayload, payer, network, "", err.Error())
	}
	record, generation, acquired, err := f.erc7710Store.Acquire(ctx, settlementKey)
	if err != nil {
		return nil, x402.NewSettleError(
			ErrERC7710SettlementFailed,
			payer,
			network,
			"",
			fmt.Sprintf("failed to reserve ERC-7710 settlement: %s", err.Error()),
		)
	}
	if !acquired {
		if record.Fingerprint != "" && record.Fingerprint != fingerprint {
			return nil, x402.NewSettleError(ErrERC7710PaymentIdentifierConflict, payer, network, "", "payment identifier is already bound to another request")
		}
		return f.resumeERC7710Settlement(
			ctx, settlementKey, generation, record, payer, network, erc7710Payload, requirements, fingerprint,
		)
	}

	record.Fingerprint = fingerprint
	if err := f.erc7710Store.Update(ctx, settlementKey, generation, record); err != nil {
		return nil, x402.NewSettleError(ErrERC7710SettlementFailed, payer, network, "", err.Error())
	}

	if _, err := f.verifyERC7710(ctx, payload, requirements, erc7710Payload, fctx, f.config.SimulateInSettle); err != nil {
		_ = f.erc7710Store.Delete(ctx, settlementKey, generation)
		verifyErr := &x402.VerifyError{}
		if errors.As(err, &verifyErr) {
			return nil, x402.NewSettleError(verifyErr.InvalidReason, verifyErr.Payer, network, "", verifyErr.InvalidMessage)
		}
		return nil, x402.NewSettleError(ErrVerificationFailed, payer, network, "", err.Error())
	}

	calldata, err := BuildERC7710RedeemCalldata(erc7710Payload, requirements)
	if err != nil {
		_ = f.erc7710Store.Delete(ctx, settlementKey, generation)
		return nil, x402.NewSettleError(ErrInvalidPayload, payer, network, "", err.Error())
	}
	dataSuffix, err := evm.ResolveDataSuffix(fctx, evm.DataSuffixContext{Payload: payload, Requirements: requirements})
	if err != nil {
		_ = f.erc7710Store.Delete(ctx, settlementKey, generation)
		return nil, x402.NewSettleError(ErrInvalidPayload, payer, network, "", err.Error())
	}
	calldata = append(calldata, dataSuffix...)
	erc7710Signer := f.signer.(evm.FacilitatorEvmSignerWithRecordedTransactions)
	caller, err := f.erc7710Caller()
	if err != nil {
		_ = f.erc7710Store.Delete(ctx, settlementKey, generation)
		return nil, x402.NewSettleError(ErrERC7710SignerUnsupported, payer, network, "", err.Error())
	}
	// The signer invokes this while holding its nonce lock, before any RPC send.
	// Persisting raw bytes closes the crash window between reservation and broadcast.
	var recordedHash string
	txHash, sendErr := erc7710Signer.SendTransactionWithGasLimitAndRecord(
		ctx, caller, erc7710Payload.DelegationManager, calldata, f.config.ERC7710GasLimit,
		func(raw []byte) error {
			var tx goethtypes.Transaction
			if err := tx.UnmarshalBinary(raw); err != nil {
				return fmt.Errorf("invalid signed transaction: %w", err)
			}
			record.Status = ERC7710SettlementBroadcast
			record.Transaction = tx.Hash().Hex()
			record.SignedTransaction = append([]byte(nil), raw...)
			if err := f.erc7710Store.Update(ctx, settlementKey, generation, record); err != nil {
				return err
			}
			recordedHash = record.Transaction
			return nil
		},
	)
	if recordedHash == "" {
		// No broadcast was permitted. A lease also recovers this claim after a crash.
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = f.erc7710Store.Delete(cleanupCtx, settlementKey, generation)
		if sendErr == nil {
			sendErr = fmt.Errorf("signer did not persist the signed transaction before broadcast")
		}
		return nil, x402.NewSettleError(ErrERC7710SettlementFailed, payer, network, "", sendErr.Error())
	}
	if !strings.EqualFold(txHash, recordedHash) || (sendErr != nil && ctx.Err() != nil) {
		message := "broadcast result is uncertain; retry the same payment"
		if sendErr != nil {
			message = evm.TruncateErrorMessage(sendErr.Error())
		}
		return nil, x402.NewSettleError(ErrSettlementPending, payer, network, recordedHash, message)
	}

	return f.awaitERC7710Settlement(
		ctx, settlementKey, generation, txHash, payer, network, erc7710Payload, requirements,
	)
}

func (f *ExactEvmScheme) resumeERC7710Settlement(
	ctx context.Context,
	settlementKey string,
	generation uint64,
	record ERC7710SettlementRecord,
	payer string,
	network x402.Network,
	erc7710Payload *evm.ExactERC7710Payload,
	requirements types.PaymentRequirements,
	fingerprint string,
) (*x402.SettleResponse, error) {
	if record.Fingerprint != "" && record.Fingerprint != fingerprint {
		return nil, x402.NewSettleError(ErrERC7710PaymentIdentifierConflict, payer, network, "", "payment identifier is already bound to another request")
	}
	switch record.Status {
	case ERC7710SettlementProcessing:
		return f.waitForERC7710Settlement(
			ctx,
			settlementKey,
			payer,
			network,
			erc7710Payload,
			requirements,
			fingerprint,
		)
	case ERC7710SettlementBroadcast:
		if len(record.SignedTransaction) > 0 {
			signer, ok := f.signer.(evm.FacilitatorEvmSignerWithRecordedTransactions)
			if !ok {
				return nil, x402.NewSettleError(ErrERC7710SignerUnsupported, payer, network, record.Transaction, "signer lacks recorded transaction support")
			}
			// A nonce error may mean this transaction already mined; its receipt is authoritative.
			_, _ = signer.SendSignedTransaction(ctx, record.SignedTransaction)
		}
		return f.awaitERC7710Settlement(
			ctx,
			settlementKey,
			generation,
			record.Transaction,
			payer,
			network,
			erc7710Payload,
			requirements,
		)
	case ERC7710SettlementSucceeded:
		return &x402.SettleResponse{
			Success:     true,
			Transaction: record.Transaction,
			Network:     network,
			Payer:       payer,
		}, nil
	case ERC7710SettlementTerminal:
		if record.ErrorReason == "" {
			record.ErrorReason = ErrERC7710SettlementFailed
		}
		return nil, x402.NewSettleError(
			record.ErrorReason,
			payer,
			network,
			record.Transaction,
			record.ErrorMessage,
		)
	default:
		return nil, x402.NewSettleError(
			ErrERC7710SettlementFailed,
			payer,
			network,
			record.Transaction,
			"invalid ERC-7710 settlement state",
		)
	}
}

func (f *ExactEvmScheme) waitForERC7710Settlement(
	ctx context.Context,
	settlementKey string,
	payer string,
	network x402.Network,
	erc7710Payload *evm.ExactERC7710Payload,
	requirements types.PaymentRequirements,
	fingerprint string,
) (*x402.SettleResponse, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for concurrent ERC-7710 settlement: %w", ctx.Err())
		case <-ticker.C:
			record, generation, found, err := f.erc7710Store.Get(ctx, settlementKey)
			if err != nil {
				return nil, fmt.Errorf("read concurrent ERC-7710 settlement: %w", err)
			}
			if !found || record.ProcessingExpired() {
				return nil, x402.NewSettleError(
					ErrERC7710SettlementFailed,
					payer,
					network,
					"",
					"concurrent settlement ended before broadcast; retry the same payment",
				)
			}
			if record.Status != ERC7710SettlementProcessing {
				return f.resumeERC7710Settlement(
					ctx,
					settlementKey,
					generation,
					record,
					payer,
					network,
					erc7710Payload,
					requirements,
					fingerprint,
				)
			}
		}
	}
}

func (f *ExactEvmScheme) awaitERC7710Settlement(
	ctx context.Context,
	settlementKey string,
	generation uint64,
	txHash string,
	payer string,
	network x402.Network,
	erc7710Payload *evm.ExactERC7710Payload,
	requirements types.PaymentRequirements,
) (*x402.SettleResponse, error) {
	receipt, err := evm.WaitForSettleReceipt(
		ctx,
		f.signer,
		txHash,
		payer,
		network,
		ErrERC7710SettlementFailed,
		ErrERC7710SettlementFailed,
	)
	if err != nil {
		settleErr := &x402.SettleError{}
		if errors.As(err, &settleErr) && settleErr.ErrorReason != ErrSettlementPending {
			_ = f.erc7710Store.Update(ctx, settlementKey, generation, ERC7710SettlementRecord{
				Status:       ERC7710SettlementTerminal,
				Transaction:  txHash,
				ErrorReason:  settleErr.ErrorReason,
				ErrorMessage: settleErr.ErrorMessage,
			})
		}
		return nil, err
	}
	amount, ok := parseERC7710Amount(requirements.Amount)
	if !ok {
		return f.terminalERC7710Settlement(
			ctx, settlementKey, generation, txHash, payer, network, ErrERC7710InvalidAmount, "",
		)
	}
	transferMatched, err := verifyEIP3009TransferEvent(
		receipt.Logs,
		common.HexToAddress(requirements.Asset),
		expectedTransferEvent{
			From:  common.HexToAddress(erc7710Payload.Delegator),
			To:    common.HexToAddress(requirements.PayTo),
			Value: amount,
		},
	)
	if err != nil {
		return f.terminalERC7710Settlement(
			ctx,
			settlementKey,
			generation,
			txHash,
			payer,
			network,
			ErrERC7710SettlementFailed,
			evm.TruncateErrorMessage(err.Error()),
		)
	}
	if !transferMatched {
		return f.terminalERC7710Settlement(
			ctx, settlementKey, generation, txHash, payer, network, ErrERC7710TransferEventMismatch, "",
		)
	}
	if err := f.erc7710Store.Update(ctx, settlementKey, generation, ERC7710SettlementRecord{
		Status:      ERC7710SettlementSucceeded,
		Transaction: txHash,
	}); err != nil {
		return nil, x402.NewSettleError(
			ErrSettlementPending,
			payer,
			network,
			txHash,
			fmt.Sprintf("settlement succeeded but failed to persist completion: %s", err.Error()),
		)
	}
	return &x402.SettleResponse{Success: true, Transaction: txHash, Network: network, Payer: payer}, nil
}

func (f *ExactEvmScheme) terminalERC7710Settlement(
	ctx context.Context,
	settlementKey string,
	generation uint64,
	txHash string,
	payer string,
	network x402.Network,
	reason string,
	message string,
) (*x402.SettleResponse, error) {
	_ = f.erc7710Store.Update(ctx, settlementKey, generation, ERC7710SettlementRecord{
		Status:       ERC7710SettlementTerminal,
		Transaction:  txHash,
		ErrorReason:  reason,
		ErrorMessage: message,
	})
	return nil, x402.NewSettleError(reason, payer, network, txHash, message)
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

func isERC7710ManagerAllowed(manager string, allowedManagers []string) bool {
	for _, allowed := range allowedManagers {
		if strings.EqualFold(strings.TrimSpace(allowed), manager) {
			return true
		}
	}
	return false
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

func erc7710SettlementKey(
	erc7710Payload *evm.ExactERC7710Payload,
	accepted types.PaymentRequirements,
	requirements types.PaymentRequirements,
) string {
	parts := []string{
		strings.ToLower(erc7710Payload.DelegationManager),
		strings.ToLower(erc7710Payload.Delegator),
		strings.ToLower(erc7710Payload.PermissionContext),
		accepted.Scheme,
		accepted.Network,
		strings.ToLower(accepted.Asset),
		canonicalERC7710Amount(accepted.Amount),
		strings.ToLower(accepted.PayTo),
		string(assetTransferMethod(accepted)),
		requirements.Scheme,
		requirements.Network,
		strings.ToLower(requirements.Asset),
		canonicalERC7710Amount(requirements.Amount),
		strings.ToLower(requirements.PayTo),
		string(assetTransferMethod(requirements)),
	}
	return crypto.Keccak256Hash([]byte(strings.Join(parts, "\x00"))).Hex()
}

func canonicalERC7710Amount(value string) string {
	if amount, ok := parseERC7710Amount(value); ok {
		return amount.String()
	}
	return value
}

// A supplied identifier names a purchase, while the fingerprint binds its terms.
// Without the extension, a permission context remains a single-payment token.
func erc7710PaymentIdentity(payload types.PaymentPayload, requirements types.PaymentRequirements, delegated *evm.ExactERC7710Payload) (string, string, error) {
	base := erc7710SettlementKey(delegated, payload.Accepted, requirements)
	id, err := paymentidentifier.ExtractPaymentIdentifier(payload, true)
	if err != nil {
		return "", "", err
	}
	if _, present := payload.Extensions[paymentidentifier.PAYMENT_IDENTIFIER]; present && id == "" {
		return "", "", fmt.Errorf("payment-identifier requires a valid id")
	}
	if id == "" {
		return base, base, nil
	}
	extensions := make(map[string]interface{}, len(payload.Extensions))
	for k, v := range payload.Extensions {
		if k != paymentidentifier.PAYMENT_IDENTIFIER {
			extensions[k] = v
		}
	}
	binding, err := json.Marshal(struct {
		Resource   *types.ResourceInfo
		Extensions map[string]interface{}
	}{payload.Resource, extensions})
	if err != nil {
		return "", "", err
	}
	fingerprint := crypto.Keccak256Hash([]byte(base), binding).Hex()
	key := crypto.Keccak256Hash([]byte(strings.Join([]string{"erc7710-payment", string(requirements.Network), strings.ToLower(delegated.Delegator), id}, "\x00"))).Hex()
	return key, fingerprint, nil
}
