package facilitator

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/x402-foundation/x402/go/v2/extensions/paymentidentifier"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	goethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

const (
	testERC7710Manager   = "0x3333333333333333333333333333333333333333"
	testERC7710Delegator = "0x4444444444444444444444444444444444444444"
	testERC7710Caller    = "0x5555555555555555555555555555555555555555"
	testERC7710GasLimit  = uint64(500_000)
)

type erc7710FacilitatorSigner struct {
	*settleMockSigner
	afterRecord   func()
	replayCalls   atomic.Int32
	simulationErr error
	sendErr       error
	simulateCalls int
	sendCalls     int
	from          string
	to            string
	data          []byte
	gasLimit      uint64
	chainID       *big.Int
	addresses     []string
	getCodeErr    error
	sendTxHash    string
}

func (s *erc7710FacilitatorSigner) GetAddresses() []string {
	if s.addresses != nil {
		return s.addresses
	}
	return []string{testERC7710Caller}
}

func (s *erc7710FacilitatorSigner) GetCode(ctx context.Context, address string) ([]byte, error) {
	if s.getCodeErr != nil {
		return nil, s.getCodeErr
	}
	return s.settleMockSigner.GetCode(ctx, address)
}

func (s *erc7710FacilitatorSigner) GetChainID(_ context.Context) (*big.Int, error) {
	if s.chainID != nil {
		return s.chainID, nil
	}
	return big.NewInt(84532), nil
}

func (s *erc7710FacilitatorSigner) SimulateTransaction(
	_ context.Context,
	from string,
	to string,
	data []byte,
	gasLimit uint64,
) error {
	s.simulateCalls++
	s.capture(from, to, data, gasLimit)
	return s.simulationErr
}

func (s *erc7710FacilitatorSigner) SendTransactionWithGasLimit(
	_ context.Context,
	from string,
	to string,
	data []byte,
	gasLimit uint64,
) (string, error) {
	s.sendCalls++
	s.capture(from, to, data, gasLimit)
	if s.sendErr != nil {
		return s.sendTxHash, s.sendErr
	}
	if s.sendTxHash != "" {
		return s.sendTxHash, nil
	}
	return erc7710TestTransaction().Hash().Hex(), nil
}

func erc7710TestTransaction() *goethtypes.Transaction {
	to := common.HexToAddress(testERC7710Manager)
	return goethtypes.NewTx(&goethtypes.LegacyTx{To: &to, Gas: testERC7710GasLimit, GasPrice: big.NewInt(1), Data: []byte{1}})
}

func (s *erc7710FacilitatorSigner) SendTransactionWithGasLimitAndRecord(ctx context.Context, from, to string, data []byte, gas uint64, record func([]byte) error) (string, error) {
	if s.sendErr != nil && s.sendTxHash == "" {
		return "", s.sendErr
	}
	raw, err := erc7710TestTransaction().MarshalBinary()
	if err != nil {
		return "", err
	}
	if err := record(raw); err != nil {
		return "", err
	}
	if s.afterRecord != nil {
		s.afterRecord()
	}
	return s.SendTransactionWithGasLimit(ctx, from, to, data, gas)
}

func (s *erc7710FacilitatorSigner) SendSignedTransaction(_ context.Context, raw []byte) (string, error) {
	s.replayCalls.Add(1)
	var tx goethtypes.Transaction
	if err := tx.UnmarshalBinary(raw); err != nil {
		return "", err
	}
	return tx.Hash().Hex(), nil
}

func (s *erc7710FacilitatorSigner) capture(from, to string, data []byte, gasLimit uint64) {
	s.from = from
	s.to = to
	s.data = append([]byte(nil), data...)
	s.gasLimit = gasLimit
}

func erc7710Fixture() (types.PaymentPayload, types.PaymentRequirements, *evm.ExactERC7710Payload) {
	requirements := types.PaymentRequirements{
		Scheme:  evm.SchemeExact,
		Network: "eip155:84532",
		Asset:   testToken,
		Amount:  "1000000",
		PayTo:   testPayTo,
		Extra: map[string]interface{}{
			"assetTransferMethod": string(evm.AssetTransferMethodERC7710),
		},
	}
	erc7710Payload := &evm.ExactERC7710Payload{
		DelegationManager: testERC7710Manager,
		PermissionContext: "0x1234",
		Delegator:         testERC7710Delegator,
	}
	return types.PaymentPayload{
		X402Version: 2,
		Accepted:    requirements,
		Payload:     erc7710Payload.ToMap(),
	}, requirements, erc7710Payload
}

func newERC7710FacilitatorSigner() *erc7710FacilitatorSigner {
	return &erc7710FacilitatorSigner{settleMockSigner: &settleMockSigner{
		codeByAddress: map[string][]byte{
			strings.ToLower(testToken):            {0x60},
			strings.ToLower(testERC7710Manager):   {0x60},
			strings.ToLower(testERC7710Delegator): {0x60},
		},
		receipt: erc7710Receipt(
			testERC7710Delegator,
			testPayTo,
			big.NewInt(1_000_000),
		),
	}}
}

func erc7710Config() *ExactEvmSchemeConfig {
	return &ExactEvmSchemeConfig{
		ERC7710GasLimit:                  testERC7710GasLimit,
		ERC7710AllowedDelegationManagers: []string{testERC7710Manager},
		ERC7710AllowInMemoryReplayStore:  true,
	}
}

func erc7710Receipt(from, to string, amount *big.Int) *evm.TransactionReceipt {
	return &evm.TransactionReceipt{
		Status: evm.TxStatusSuccess,
		Logs: []*goethtypes.Log{{
			Address: common.HexToAddress(testToken),
			Topics: []common.Hash{
				crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)")),
				common.BytesToHash(common.HexToAddress(from).Bytes()),
				common.BytesToHash(common.HexToAddress(to).Bytes()),
			},
			Data: common.LeftPadBytes(amount.Bytes(), 32),
		}},
	}
}

func TestBuildERC7710RedeemCalldata(t *testing.T) {
	_, requirements, erc7710Payload := erc7710Fixture()
	calldata, err := BuildERC7710RedeemCalldata(erc7710Payload, requirements)
	if err != nil {
		t.Fatalf("BuildERC7710RedeemCalldata failed: %v", err)
	}

	managerABI, err := abi.JSON(strings.NewReader(string(evm.ERC7710RedeemDelegationsABI)))
	if err != nil {
		t.Fatal(err)
	}
	method := managerABI.Methods[evm.FunctionRedeemDelegations]
	if !bytes.Equal(calldata[:4], method.ID) {
		t.Fatalf("unexpected selector: %x", calldata[:4])
	}
	arguments, err := method.Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("decode redeemDelegations: %v", err)
	}
	contexts := arguments[0].([][]byte)
	modes := arguments[1].([][32]byte)
	executions := arguments[2].([][]byte)
	if len(contexts) != 1 || !bytes.Equal(contexts[0], []byte{0x12, 0x34}) {
		t.Fatalf("unexpected permission contexts: %x", contexts)
	}
	if len(modes) != 1 || modes[0] != ([32]byte{}) {
		t.Fatalf("unexpected ERC-7579 mode: %x", modes)
	}
	if len(executions) != 1 || len(executions[0]) != 120 {
		t.Fatalf("unexpected execution calldata length: %d", len(executions[0]))
	}
	execution := executions[0]
	if !bytes.Equal(execution[:20], common.HexToAddress(testToken).Bytes()) {
		t.Fatalf("execution target mismatch: %x", execution[:20])
	}
	if !bytes.Equal(execution[20:52], make([]byte, 32)) {
		t.Fatal("single execution ETH value must be zero")
	}
	if !bytes.Equal(execution[52:56], common.FromHex("0xa9059cbb")) {
		t.Fatalf("unexpected transfer selector: %x", execution[52:56])
	}
	if !bytes.Equal(execution[68:88], common.HexToAddress(testPayTo).Bytes()) {
		t.Fatalf("transfer recipient mismatch: %x", execution[68:88])
	}
	if got := new(big.Int).SetBytes(execution[88:120]).String(); got != requirements.Amount {
		t.Fatalf("transfer amount mismatch: %s", got)
	}
}

func TestVerifyERC7710SimulatesWithFacilitatorCallerAndGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	response, err := scheme.Verify(context.Background(), payload, requirements, nil)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !response.IsValid || response.Payer != testERC7710Delegator {
		t.Fatalf("unexpected response: %+v", response)
	}
	if signer.simulateCalls != 1 || signer.from != testERC7710Caller ||
		signer.to != testERC7710Manager || signer.gasLimit != testERC7710GasLimit {
		t.Fatalf("unexpected simulation: %+v", signer)
	}
}

func TestVerifyERC7710RejectsSimulationFailure(t *testing.T) {
	for name, simulationErr := range map[string]error{
		"revert":         errors.New("execution reverted: caveat violation"),
		"out of gas":     errors.New("VM execution error: out of gas"),
		"invalid opcode": errors.New("invalid opcode: 0xfe"),
	} {
		t.Run(name, func(t *testing.T) {
			payload, requirements, _ := erc7710Fixture()
			signer := newERC7710FacilitatorSigner()
			signer.simulationErr = simulationErr
			scheme := NewExactEvmScheme(signer, erc7710Config())

			_, err := scheme.Verify(context.Background(), payload, requirements, nil)
			assertERC7710VerifyReason(t, err, ErrERC7710SimulationFailed)
		})
	}
}

func TestVerifyERC7710ReturnsTransientSimulationFailure(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.simulationErr = context.DeadlineExceeded
	scheme := NewExactEvmScheme(signer, erc7710Config())

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	if err == nil {
		t.Fatal("expected transient simulation error")
	}
	verifyErr := &x402.VerifyError{}
	if errors.As(err, &verifyErr) {
		t.Fatalf("RPC failure must not invalidate payment: %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected wrapped deadline error, got %v", err)
	}
}

func TestVerifyERC7710RequiresConfiguredGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), nil)

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710GasLimitRequired)
}

func TestVerifyERC7710RequiresTrustedDelegationManager(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()

	t.Run("empty allowlist disables ERC-7710", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		config := erc7710Config()
		config.ERC7710AllowedDelegationManagers = nil
		scheme := NewExactEvmScheme(signer, config)

		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710DelegationManagerNotAllowed)
		if signer.simulateCalls != 0 {
			t.Fatal("untrusted manager reached simulation")
		}
	})

	t.Run("deployed no-op manager is rejected", func(t *testing.T) {
		const noOpManager = "0x6666666666666666666666666666666666666666"
		payload, requirements, _ := erc7710Fixture()
		payload.Payload["delegationManager"] = noOpManager
		signer := newERC7710FacilitatorSigner()
		signer.codeByAddress[strings.ToLower(noOpManager)] = []byte{0x60}
		scheme := NewExactEvmScheme(signer, erc7710Config())

		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710DelegationManagerNotAllowed)
		if signer.simulateCalls != 0 {
			t.Fatal("deployed no-op manager reached simulation")
		}
	})
}

func TestVerifyERC7710RequiresDurableReplayStoreByDefault(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	config := erc7710Config()
	config.ERC7710AllowInMemoryReplayStore = false
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), config)

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710ReplayStoreRequired)

	scheme.SetERC7710SettlementStore(NewInMemoryERC7710SettlementStore())
	response, err := scheme.Verify(context.Background(), payload, requirements, nil)
	if err != nil || !response.IsValid {
		t.Fatalf("injected replay store rejected: %v %+v", err, response)
	}
}

func TestVerifyERC7710RejectsSignerNetworkMismatch(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.chainID = big.NewInt(1)
	scheme := NewExactEvmScheme(signer, erc7710Config())

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrNetworkMismatch)
}

func TestVerifyERC7710RejectsPermissionContextOutsideGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permissionContext"] = "0x" + strings.Repeat("00", 130_000)
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710CalldataExceedsGasLimit)
	if signer.simulateCalls != 0 {
		t.Fatal("oversized permissionContext reached simulation")
	}
}

func TestVerifyRoutesMalformedERC7710BeforePermit2(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permit2Authorization"] = map[string]interface{}{}
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), erc7710Config())

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrInvalidPayload)
}

func TestSettleERC7710SimulatesWhenConfiguredAndSendsWithGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	config := erc7710Config()
	config.SimulateInSettle = true
	scheme := NewExactEvmScheme(signer, config)

	response, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil {
		t.Fatalf("Settle failed: %v", err)
	}
	if !response.Success || response.Payer != testERC7710Delegator {
		t.Fatalf("unexpected response: %+v", response)
	}
	if signer.simulateCalls != 1 || signer.sendCalls != 1 {
		t.Fatalf("expected one simulation and send, got simulate=%d send=%d", signer.simulateCalls, signer.sendCalls)
	}
	if signer.from != testERC7710Caller || signer.to != testERC7710Manager ||
		signer.gasLimit != testERC7710GasLimit {
		t.Fatalf("unexpected transaction parameters: %+v", signer)
	}
}

func TestSettleERC7710SkipsSimulationUnlessConfigured(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	response, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil {
		t.Fatalf("Settle failed: %v", err)
	}
	if !response.Success || signer.simulateCalls != 0 || signer.sendCalls != 1 {
		t.Fatalf("expected send without simulation, got resp=%+v simulate=%d send=%d", response, signer.simulateCalls, signer.sendCalls)
	}
}

func TestSettleERC7710RejectsSendFailure(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.sendErr = errors.New("replacement transaction underpriced")
	scheme := NewExactEvmScheme(signer, erc7710Config())

	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, err, ErrERC7710SettlementFailed, "")
	_, retryErr := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, retryErr, ErrERC7710SettlementFailed, "")
	if signer.sendCalls != 0 {
		t.Fatal("preparation failure broadcast a transaction")
	}
}

func TestSettleERC7710ReconcilesSendErrorWithHash(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	successHash := erc7710TestTransaction().Hash().Hex()
	signer := newERC7710FacilitatorSigner()
	signer.sendTxHash = successHash
	signer.sendErr = errors.New("rpc response lost after broadcast")
	signer.receiptErr = errors.New("rpc: timeout waiting for receipt")
	scheme := NewExactEvmScheme(signer, erc7710Config())

	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettlementPending(t, err, successHash)
	signer.receiptErr = nil
	retry, retryErr := scheme.Settle(context.Background(), payload, requirements, nil)
	if retryErr != nil || retry.Transaction != successHash {
		t.Fatalf("lost-response retry failed: %v %+v", retryErr, retry)
	}
	if signer.sendCalls != 1 {
		t.Fatalf("lost-response retry broadcast %d transactions", signer.sendCalls)
	}
}

func TestSettleERC7710ClassifiesTransientSimulationFailure(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.simulationErr = context.DeadlineExceeded
	config := erc7710Config()
	config.SimulateInSettle = true
	scheme := NewExactEvmScheme(signer, config)

	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, err, ErrVerificationFailed, "")
	if signer.sendCalls != 0 {
		t.Fatal("settlement broadcast after transient simulation failure")
	}
}

func TestSettleERC7710RequiresExactTransferReceipt(t *testing.T) {
	successHash := erc7710TestTransaction().Hash().Hex()
	tests := map[string]func(*evm.TransactionReceipt){
		"missing log": func(receipt *evm.TransactionReceipt) {
			receipt.Logs = nil
		},
		"wrong token": func(receipt *evm.TransactionReceipt) {
			receipt.Logs[0].Address = common.HexToAddress("0x6666666666666666666666666666666666666666")
		},
		"wrong delegator": func(receipt *evm.TransactionReceipt) {
			receipt.Logs[0].Topics[1] = common.HexToHash("0x7777777777777777777777777777777777777777")
		},
		"wrong recipient": func(receipt *evm.TransactionReceipt) {
			receipt.Logs[0].Topics[2] = common.HexToHash("0x8888888888888888888888888888888888888888")
		},
		"wrong amount": func(receipt *evm.TransactionReceipt) {
			receipt.Logs[0].Data = common.LeftPadBytes(big.NewInt(999_999).Bytes(), 32)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload, requirements, _ := erc7710Fixture()
			signer := newERC7710FacilitatorSigner()
			mutate(signer.receipt)
			scheme := NewExactEvmScheme(signer, erc7710Config())

			_, err := scheme.Settle(context.Background(), payload, requirements, nil)
			assertSettleErr(t, err, ErrERC7710TransferEventMismatch, successHash)

			_, retryErr := scheme.Settle(context.Background(), payload, requirements, nil)
			assertSettleErr(t, retryErr, ErrERC7710TransferEventMismatch, successHash)
			if signer.sendCalls != 1 {
				t.Fatalf("terminal receipt retry broadcast %d transactions", signer.sendCalls)
			}
		})
	}
}

func TestVerifyERC7710RejectsInvalidAcceptedAndRequirements(t *testing.T) {
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), erc7710Config())
	overflowAmount := new(big.Int).Lsh(big.NewInt(1), 256).String()

	tests := map[string]struct {
		mutate func(*types.PaymentPayload, *types.PaymentRequirements)
		reason string
	}{
		"scheme mismatch": {
			mutate: func(payload *types.PaymentPayload, _ *types.PaymentRequirements) {
				payload.Accepted.Scheme = evm.SchemeUpto
			},
			reason: ErrInvalidScheme,
		},
		"accepted network mismatch": {
			mutate: func(payload *types.PaymentPayload, _ *types.PaymentRequirements) {
				payload.Accepted.Network = "eip155:8453"
			},
			reason: ErrNetworkMismatch,
		},
		"payTo mismatch": {
			mutate: func(payload *types.PaymentPayload, _ *types.PaymentRequirements) {
				payload.Accepted.PayTo = "0x6666666666666666666666666666666666666666"
			},
			reason: ErrERC7710AcceptedMismatch,
		},
		"amount mismatch": {
			mutate: func(payload *types.PaymentPayload, _ *types.PaymentRequirements) {
				payload.Accepted.Amount = "1"
			},
			reason: ErrERC7710AcceptedMismatch,
		},
		"invalid amount": {
			mutate: func(payload *types.PaymentPayload, requirements *types.PaymentRequirements) {
				payload.Accepted.Amount = "0"
				requirements.Amount = "0"
			},
			reason: ErrERC7710InvalidAmount,
		},
		"overflow amount": {
			mutate: func(payload *types.PaymentPayload, requirements *types.PaymentRequirements) {
				payload.Accepted.Amount = overflowAmount
				requirements.Amount = overflowAmount
			},
			reason: ErrERC7710InvalidAmount,
		},
		"zero payTo": {
			mutate: func(payload *types.PaymentPayload, requirements *types.PaymentRequirements) {
				payload.Accepted.PayTo = "0x" + strings.Repeat("0", 40)
				requirements.PayTo = payload.Accepted.PayTo
			},
			reason: ErrERC7710InvalidAddress,
		},
		"accepted method not erc7710": {
			mutate: func(payload *types.PaymentPayload, _ *types.PaymentRequirements) {
				payload.Accepted.Extra = map[string]interface{}{
					"assetTransferMethod": string(evm.AssetTransferMethodPermit2),
				}
			},
			reason: ErrERC7710InvalidMethod,
		},
		"requirements method not erc7710": {
			mutate: func(_ *types.PaymentPayload, requirements *types.PaymentRequirements) {
				requirements.Extra = map[string]interface{}{
					"assetTransferMethod": string(evm.AssetTransferMethodEIP3009),
				}
			},
			reason: ErrERC7710InvalidMethod,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			payload, requirements, _ := erc7710Fixture()
			test.mutate(&payload, &requirements)
			_, err := scheme.Verify(context.Background(), payload, requirements, nil)
			assertERC7710VerifyReason(t, err, test.reason)
		})
	}
}

func TestVerifyERC7710AcceptsChecksummedAssetAndPayTo(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Accepted.Asset = "0x" + strings.ToUpper(strings.TrimPrefix(payload.Accepted.Asset, "0x"))
	payload.Accepted.PayTo = strings.ToLower(payload.Accepted.PayTo)
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), erc7710Config())

	response, err := scheme.Verify(context.Background(), payload, requirements, nil)
	if err != nil || !response.IsValid {
		t.Fatalf("checksummed addresses should match: %v %+v", err, response)
	}
}

func TestVerifyERC7710RejectsUndeployedContracts(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()

	t.Run("delegation manager", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		delete(signer.codeByAddress, strings.ToLower(testERC7710Manager))
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710DelegationManagerNotFound)
	})
	t.Run("delegator", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		delete(signer.codeByAddress, strings.ToLower(testERC7710Delegator))
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710DelegatorNotDeployed)
	})
	t.Run("asset", func(t *testing.T) {
		evm.ResetAssetContractCache()
		signer := newERC7710FacilitatorSigner()
		delete(signer.codeByAddress, strings.ToLower(testToken))
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, evm.ErrAssetNotDeployedContract)
	})
}

func TestVerifyERC7710RejectsUnsupportedSignerAndCaller(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()

	t.Run("no gas-limited interface", func(t *testing.T) {
		signer := &settleMockSigner{codeByAddress: map[string][]byte{
			strings.ToLower(testToken):            {0x60},
			strings.ToLower(testERC7710Manager):   {0x60},
			strings.ToLower(testERC7710Delegator): {0x60},
		}}
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710SignerUnsupported)
	})
	t.Run("empty caller", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		signer.addresses = []string{}
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710SignerUnsupported)
	})
	t.Run("zero caller", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		signer.addresses = []string{"0x" + strings.Repeat("0", 40)}
		scheme := NewExactEvmScheme(signer, erc7710Config())
		_, err := scheme.Verify(context.Background(), payload, requirements, nil)
		assertERC7710VerifyReason(t, err, ErrERC7710SignerUnsupported)
	})
}

func TestVerifyERC7710RoutesRequirementsWithoutPayloadFields(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload = map[string]interface{}{"signature": "0x12"}
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), erc7710Config())

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrInvalidPayload)
}

func TestSettleERC7710RoutesMalformedPayload(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permissionContext"] = "0x"
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), erc7710Config())

	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, err, ErrInvalidPayload, "")
}

func TestSettleERC7710WrapsVerifyFailure(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), nil)

	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, err, ErrERC7710GasLimitRequired, "")
}

func TestVerifyAndSettleERC7710AppendDataSuffix(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	config := erc7710Config()
	config.SimulateInSettle = true
	scheme := NewExactEvmScheme(signer, config)
	suffix := []byte{0xde, 0xad}
	fctx := x402.NewFacilitatorContext(map[string]x402.FacilitatorExtension{
		evm.BuilderCodeKey: &erc7710SuffixExtension{suffix: suffix},
	})

	if _, err := scheme.Verify(context.Background(), payload, requirements, fctx); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !bytes.HasSuffix(signer.data, suffix) {
		t.Fatalf("simulation calldata missing suffix: %x", signer.data)
	}

	if _, err := scheme.Settle(context.Background(), payload, requirements, fctx); err != nil {
		t.Fatalf("Settle failed: %v", err)
	}
	if !bytes.HasSuffix(signer.data, suffix) {
		t.Fatalf("settlement calldata missing suffix: %x", signer.data)
	}
}

func TestSettleERC7710ReplayStore(t *testing.T) {
	settlementKeyFor := func(payload types.PaymentPayload, requirements types.PaymentRequirements) string {
		parsed, err := evm.ERC7710PayloadFromMap(payload.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return erc7710SettlementKey(parsed, payload.Accepted, requirements)
	}
	successHash := erc7710TestTransaction().Hash().Hex()

	t.Run("success persists and prevents rebroadcast", func(t *testing.T) {
		payload, requirements, _ := erc7710Fixture()
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := NewInMemoryERC7710SettlementStore()
		scheme.SetERC7710SettlementStore(store)

		resp, err := scheme.Settle(context.Background(), payload, requirements, nil)
		if err != nil || !resp.Success {
			t.Fatalf("Settle failed: %v %+v", err, resp)
		}
		record, _, acquired, err := store.Acquire(context.Background(), settlementKeyFor(payload, requirements))
		if err != nil || acquired || record.Status != ERC7710SettlementSucceeded || record.Transaction != successHash {
			t.Fatalf("unexpected completed record: %+v acquired=%v err=%v", record, acquired, err)
		}

		retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
		if err != nil || retry.Transaction != successHash {
			t.Fatalf("retry failed: %v %+v", err, retry)
		}
		if signer.sendCalls != 1 {
			t.Fatalf("completed retry rebroadcast %d transactions", signer.sendCalls)
		}
	})

	t.Run("receipt failure populates store", func(t *testing.T) {
		payload, requirements, _ := erc7710Fixture()
		signer := newERC7710FacilitatorSigner()
		signer.receiptErr = errors.New("rpc: timeout waiting for receipt")
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := NewInMemoryERC7710SettlementStore()
		scheme.SetERC7710SettlementStore(store)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettlementPending(t, err, successHash)
		record, _, acquired, acquireErr := store.Acquire(context.Background(), settlementKeyFor(payload, requirements))
		if acquireErr != nil || acquired ||
			record.Status != ERC7710SettlementBroadcast ||
			record.Transaction != successHash {
			t.Fatalf("unexpected pending record: %+v acquired=%v err=%v", record, acquired, acquireErr)
		}

		signer.receiptErr = nil
		retry, retryErr := scheme.Settle(context.Background(), payload, requirements, nil)
		if retryErr != nil || retry.Transaction != successHash {
			t.Fatalf("pending retry failed: %v %+v", retryErr, retry)
		}
		if signer.sendCalls != 1 {
			t.Fatalf("pending retry rebroadcast %d transactions", signer.sendCalls)
		}
	})

	t.Run("cache hit reconciles without resend", func(t *testing.T) {
		payload, requirements, _ := erc7710Fixture()
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := NewInMemoryERC7710SettlementStore()
		scheme.SetERC7710SettlementStore(store)
		prior := "0x" + strings.Repeat("ab", 32)
		key := settlementKeyFor(payload, requirements)
		_, generation, acquired, err := store.Acquire(context.Background(), key)
		if err != nil || !acquired {
			t.Fatalf("reserve settlement: acquired=%v err=%v", acquired, err)
		}
		if err := store.Update(context.Background(), key, generation, ERC7710SettlementRecord{
			Status: ERC7710SettlementBroadcast, Transaction: prior,
		}); err != nil {
			t.Fatal(err)
		}

		resp, err := scheme.Settle(context.Background(), payload, requirements, nil)
		if err != nil || resp.Transaction != prior {
			t.Fatalf("expected reconcile %s: %v %+v", prior, err, resp)
		}
		if signer.sendCalls != 0 || signer.simulateCalls != 0 {
			t.Fatalf("cache hit must not re-broadcast, send=%d simulate=%d", signer.sendCalls, signer.simulateCalls)
		}
		record, _, acquired, err := store.Acquire(context.Background(), key)
		if err != nil || acquired || record.Status != ERC7710SettlementSucceeded {
			t.Fatalf("unexpected reconciled record: %+v acquired=%v err=%v", record, acquired, err)
		}
	})

	t.Run("verify failure never touches store", func(t *testing.T) {
		payload, requirements, _ := erc7710Fixture()
		scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), nil)
		store := NewInMemoryERC7710SettlementStore()
		scheme.SetERC7710SettlementStore(store)
		key := settlementKeyFor(payload, requirements)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettleErr(t, err, ErrERC7710GasLimitRequired, "")
		if _, _, acquired, acquireErr := store.Acquire(context.Background(), key); acquireErr != nil || !acquired {
			t.Fatalf("verify failure left a record: acquired=%v err=%v", acquired, acquireErr)
		}
	})

	t.Run("invalid broadcast response retains persisted transaction", func(t *testing.T) {
		payload, requirements, _ := erc7710Fixture()
		signer := newERC7710FacilitatorSigner()
		signer.sendTxHash = "0xnothash"
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := NewInMemoryERC7710SettlementStore()
		scheme.SetERC7710SettlementStore(store)
		key := settlementKeyFor(payload, requirements)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettlementPending(t, err, erc7710TestTransaction().Hash().Hex())
		record, _, acquired, acquireErr := store.Acquire(context.Background(), key)
		if acquireErr != nil || acquired || record.Status != ERC7710SettlementBroadcast {
			t.Fatalf("invalid hash record: %+v acquired=%v err=%v", record, acquired, acquireErr)
		}
	})
}

func TestSettleERC7710ConcurrentCallsBroadcastOnce(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	const calls = 32
	results := make(chan error, calls)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(calls)
	for range calls {
		go func() {
			defer wg.Done()
			<-start
			_, err := scheme.Settle(context.Background(), payload, requirements, nil)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if signer.sendCalls != 1 {
		t.Fatalf("concurrent settle broadcast %d transactions", signer.sendCalls)
	}
	retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || !retry.Success {
		t.Fatalf("completed retry failed: %v %+v", err, retry)
	}
	if signer.sendCalls != 1 {
		t.Fatalf("completed retry rebroadcast %d transactions", signer.sendCalls)
	}
}

func TestSettleERC7710CanonicalReplayDoesNotRebroadcast(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permissionContext"] = "0xabcd"
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	first, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || !first.Success {
		t.Fatalf("first settle failed: %v %+v", err, first)
	}

	payload.Payload["permissionContext"] = "0xABCD"
	payload.Accepted.Amount = "0" + payload.Accepted.Amount
	retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || retry.Transaction != first.Transaction {
		t.Fatalf("canonical retry failed: %v %+v", err, retry)
	}
	if signer.sendCalls != 1 {
		t.Fatalf("canonical retry broadcast %d transactions", signer.sendCalls)
	}
}

func TestSettleERC7710StoreFailuresFailClosed(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	successHash := erc7710TestTransaction().Hash().Hex()

	t.Run("acquire failure prevents broadcast", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := &failingERC7710SettlementStore{
			InMemoryERC7710SettlementStore: NewInMemoryERC7710SettlementStore(),
			acquireErr:                     errors.New("store unavailable"),
		}
		scheme.SetERC7710SettlementStore(store)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettleErr(t, err, ErrERC7710SettlementFailed, "")
		if signer.sendCalls != 0 {
			t.Fatal("store reservation failure reached broadcast")
		}
	})

	t.Run("reservation fence failure prevents broadcast", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := &failingERC7710SettlementStore{
			InMemoryERC7710SettlementStore: NewInMemoryERC7710SettlementStore(),
			failUpdate:                     1,
		}
		scheme.SetERC7710SettlementStore(store)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettleErr(t, err, ErrERC7710SettlementFailed, "")
		if signer.sendCalls != 0 {
			t.Fatal("reservation fence failure reached broadcast")
		}
	})

	t.Run("persistence failure prevents broadcast and permits recovery", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := &failingERC7710SettlementStore{InMemoryERC7710SettlementStore: NewInMemoryERC7710SettlementStore(), failUpdate: 2}
		scheme.SetERC7710SettlementStore(store)
		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettleErr(t, err, ErrERC7710SettlementFailed, "")
		if signer.sendCalls != 0 {
			t.Fatal("broadcast preceded durable persistence")
		}
		retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
		if err != nil || !retry.Success || signer.sendCalls != 1 {
			t.Fatalf("recovery: %+v %v sends=%d", retry, err, signer.sendCalls)
		}
	})

	t.Run("completion persistence failure reconciles original hash", func(t *testing.T) {
		signer := newERC7710FacilitatorSigner()
		scheme := NewExactEvmScheme(signer, erc7710Config())
		store := &failingERC7710SettlementStore{
			InMemoryERC7710SettlementStore: NewInMemoryERC7710SettlementStore(),
			failUpdate:                     3,
		}
		scheme.SetERC7710SettlementStore(store)

		_, err := scheme.Settle(context.Background(), payload, requirements, nil)
		assertSettleErr(t, err, ErrSettlementPending, successHash)
		retry, retryErr := scheme.Settle(context.Background(), payload, requirements, nil)
		if retryErr != nil || retry.Transaction != successHash {
			t.Fatalf("completion retry failed: %v %+v", retryErr, retry)
		}
		if signer.sendCalls != 1 {
			t.Fatalf("completion retry broadcast %d transactions", signer.sendCalls)
		}
	})
}

func TestERC7710SettlementKeyBindsContextAndRequirements(t *testing.T) {
	payload, requirements, parsed := erc7710Fixture()
	base := erc7710SettlementKey(parsed, payload.Accepted, requirements)
	assertDifferent := func(name string, changed *evm.ExactERC7710Payload, accepted, required types.PaymentRequirements) {
		t.Helper()
		if got := erc7710SettlementKey(changed, accepted, required); got == base {
			t.Fatalf("%s did not change settlement key", name)
		}
	}

	changedPayload := *parsed
	changedPayload.PermissionContext = "0x5678"
	assertDifferent("permission context", &changedPayload, payload.Accepted, requirements)

	changedPayload = *parsed
	changedPayload.PermissionContext = "0xABCD"
	lowercasePayload := changedPayload
	lowercasePayload.PermissionContext = "0xabcd"
	if got := erc7710SettlementKey(&changedPayload, payload.Accepted, requirements); got !=
		erc7710SettlementKey(&lowercasePayload, payload.Accepted, requirements) {
		t.Fatal("hex case changed settlement key")
	}

	changedPayload = *parsed
	changedPayload.DelegationManager = "0x6666666666666666666666666666666666666666"
	assertDifferent("delegation manager", &changedPayload, payload.Accepted, requirements)

	changedPayload = *parsed
	changedPayload.Delegator = "0x6666666666666666666666666666666666666666"
	assertDifferent("delegator", &changedPayload, payload.Accepted, requirements)

	changedAccepted := payload.Accepted
	changedAccepted.Amount = "999999"
	assertDifferent("accepted requirements", parsed, changedAccepted, requirements)

	changedAccepted = payload.Accepted
	changedAccepted.Amount = "0" + changedAccepted.Amount
	if got := erc7710SettlementKey(parsed, changedAccepted, requirements); got != base {
		t.Fatal("equivalent amount encoding changed settlement key")
	}

	changedRequirements := requirements
	changedRequirements.PayTo = "0x7777777777777777777777777777777777777777"
	assertDifferent("server requirements", parsed, payload.Accepted, changedRequirements)
}

func TestInMemoryERC7710SettlementStoreRetainsCompleted(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryERC7710SettlementStore()
	_, generation, acquired, err := store.Acquire(ctx, "payment")
	if err != nil || !acquired {
		t.Fatalf("Acquire: acquired=%v err=%v", acquired, err)
	}
	completed := ERC7710SettlementRecord{
		Status:      ERC7710SettlementSucceeded,
		Transaction: erc7710TestTransaction().Hash().Hex(),
	}
	if err := store.Update(ctx, "payment", generation, completed); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		record, gotGeneration, acquired, err := store.Acquire(ctx, "payment")
		if err != nil || acquired || gotGeneration != generation || !reflect.DeepEqual(record, completed) {
			t.Fatalf(
				"completed record not retained: %+v generation=%d acquired=%v err=%v",
				record,
				gotGeneration,
				acquired,
				err,
			)
		}
	}
}

func TestInMemoryERC7710SettlementStoreFencesStaleGeneration(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryERC7710SettlementStore()
	_, staleGeneration, acquired, err := store.Acquire(ctx, "payment")
	if err != nil || !acquired {
		t.Fatalf("first Acquire: acquired=%v err=%v", acquired, err)
	}
	if err := store.Delete(ctx, "payment", staleGeneration); err != nil {
		t.Fatal(err)
	}
	currentRecord, currentGeneration, acquired, err := store.Acquire(ctx, "payment")
	if err != nil || !acquired || currentGeneration == staleGeneration {
		t.Fatalf("second Acquire: generation=%d acquired=%v err=%v", currentGeneration, acquired, err)
	}
	if err := store.Update(ctx, "payment", staleGeneration, ERC7710SettlementRecord{
		Status: ERC7710SettlementSucceeded,
	}); err == nil {
		t.Fatal("stale Update succeeded")
	}
	if err := store.Delete(ctx, "payment", staleGeneration); err == nil {
		t.Fatal("stale Delete succeeded")
	}
	record, generation, acquired, err := store.Acquire(ctx, "payment")
	if err != nil || acquired || generation != currentGeneration || !reflect.DeepEqual(record, currentRecord) {
		t.Fatalf("completed record not retained: %+v acquired=%v err=%v", record, acquired, err)
	}
}

type failingERC7710SettlementStore struct {
	*InMemoryERC7710SettlementStore
	acquireErr error
	failUpdate int
	updateCall int
}

func (s *failingERC7710SettlementStore) Acquire(
	ctx context.Context,
	key string,
) (ERC7710SettlementRecord, uint64, bool, error) {
	if s.acquireErr != nil {
		return ERC7710SettlementRecord{}, 0, false, s.acquireErr
	}
	return s.InMemoryERC7710SettlementStore.Acquire(ctx, key)
}

func (s *failingERC7710SettlementStore) Update(
	ctx context.Context,
	key string,
	generation uint64,
	record ERC7710SettlementRecord,
) error {
	s.updateCall++
	if s.updateCall == s.failUpdate {
		return errors.New("store unavailable")
	}
	return s.InMemoryERC7710SettlementStore.Update(ctx, key, generation, record)
}

func TestVerifyDoesNotRouteEIP3009OrPermit2ThroughERC7710(t *testing.T) {
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())

	eip3009Payload, eip3009Requirements := plainEIP3009Payload(t)
	_, _ = scheme.Verify(context.Background(), eip3009Payload, eip3009Requirements, nil)
	if signer.simulateCalls != 0 {
		t.Fatal("EIP-3009 verify must not call ERC-7710 simulation")
	}

	permit2Payload, permit2Requirements, _ := plainPermit2Payload()
	_, _ = scheme.Verify(context.Background(), permit2Payload, permit2Requirements, nil)
	if signer.simulateCalls != 0 {
		t.Fatal("Permit2 verify must not call ERC-7710 simulation")
	}
}

func TestBuildERC7710RedeemCalldataRejectsInvalidInputs(t *testing.T) {
	_, requirements, erc7710Payload := erc7710Fixture()

	if _, err := BuildERC7710RedeemCalldata(nil, requirements); err == nil {
		t.Fatal("expected nil payload error")
	}
	badAmount := requirements
	badAmount.Amount = "0"
	if _, err := BuildERC7710RedeemCalldata(erc7710Payload, badAmount); err == nil {
		t.Fatal("expected invalid amount error")
	}
	badPayTo := requirements
	badPayTo.PayTo = "0x" + strings.Repeat("0", 40)
	if _, err := BuildERC7710RedeemCalldata(erc7710Payload, badPayTo); err == nil {
		t.Fatal("expected invalid payTo error")
	}
	badContext := *erc7710Payload
	badContext.PermissionContext = "0x"
	if _, err := BuildERC7710RedeemCalldata(&badContext, requirements); err == nil {
		t.Fatal("expected invalid permissionContext error")
	}
}

type erc7710SuffixExtension struct {
	suffix []byte
}

func (e *erc7710SuffixExtension) Key() string { return evm.BuilderCodeKey }

func (e *erc7710SuffixExtension) BuildDataSuffix(evm.DataSuffixContext) ([]byte, error) {
	return e.suffix, nil
}

func assertERC7710VerifyReason(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error", expected)
	}
	verifyErr := &x402.VerifyError{}
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected VerifyError, got %T: %v", err, err)
	}
	if verifyErr.InvalidReason != expected {
		t.Fatalf("expected %s, got %s", expected, verifyErr.InvalidReason)
	}
}

func withERC7710PaymentID(payload types.PaymentPayload, id string) types.PaymentPayload {
	payload.Extensions = map[string]interface{}{paymentidentifier.PAYMENT_IDENTIFIER: paymentidentifier.DeclarePaymentIdentifierExtension(false)}
	_ = paymentidentifier.AppendPaymentIdentifierToExtensions(payload.Extensions, id)
	return payload
}

func TestERC7710MultiUsePurchasesAndConflictingIDs(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())
	first := withERC7710PaymentID(payload, "pay_first_purchase")
	second := withERC7710PaymentID(payload, "pay_second_purchase")
	for _, request := range []types.PaymentPayload{first, first, second, second} {
		if response, err := scheme.Settle(context.Background(), request, requirements, nil); err != nil || !response.Success {
			t.Fatalf("settle: %+v %v", response, err)
		}
	}
	if signer.sendCalls != 2 {
		t.Fatalf("two purchases sent %d transactions", signer.sendCalls)
	}
	changed := first
	changed.Resource = &types.ResourceInfo{URL: "https://seller.test/another-operation"}
	_, err := scheme.Settle(context.Background(), changed, requirements, nil)
	assertSettleErr(t, err, ErrERC7710PaymentIdentifierConflict, "")
	changed = first
	changed.Accepted.Amount = "2"
	changedRequirements := requirements
	changedRequirements.Amount = "2"
	_, err = scheme.Settle(context.Background(), changed, changedRequirements, nil)
	assertSettleErr(t, err, ErrERC7710PaymentIdentifierConflict, "")
	if signer.sendCalls != 2 {
		t.Fatal("conflicting request broadcast")
	}
}

func TestERC7710RecoversPersistedTransactionAfterRestart(t *testing.T) {
	payload, requirements, delegated := erc7710Fixture()
	store := NewInMemoryERC7710SettlementStore()
	key, fingerprint, err := erc7710PaymentIdentity(payload, requirements, delegated)
	if err != nil {
		t.Fatal(err)
	}
	record, generation, _, _ := store.Acquire(context.Background(), key)
	raw, _ := erc7710TestTransaction().MarshalBinary()
	record.Status, record.Fingerprint = ERC7710SettlementBroadcast, fingerprint
	record.Transaction, record.SignedTransaction = erc7710TestTransaction().Hash().Hex(), raw
	if err := store.Update(context.Background(), key, generation, record); err != nil {
		t.Fatal(err)
	}
	// Simulate death after persisting but before the first RPC send.
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())
	scheme.SetERC7710SettlementStore(store)
	response, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || response.Transaction != record.Transaction || signer.sendCalls != 0 || signer.replayCalls.Load() != 1 {
		t.Fatalf("restart recovery: %+v %v", response, err)
	}
}

func TestERC7710ExpiredPreparationFencesOldWorker(t *testing.T) {
	store := NewInMemoryERC7710SettlementStore()
	record, old, _, _ := store.Acquire(context.Background(), "payment")
	record.LeaseExpiresAt = time.Now().Add(-time.Minute)
	if err := store.Update(context.Background(), "payment", old, record); err != nil {
		t.Fatal(err)
	}
	_, generation, acquired, err := store.Acquire(context.Background(), "payment")
	if err != nil || !acquired || old == generation {
		t.Fatalf("expired acquisition: %d %v %v", generation, acquired, err)
	}
	if err := store.Update(context.Background(), "payment", old, ERC7710SettlementRecord{Status: ERC7710SettlementBroadcast}); err == nil {
		t.Fatal("stale sender permitted to broadcast")
	}
}

func TestERC7710CanceledSendReconcilesOnFreshContext(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer.afterRecord = cancel
	signer.sendTxHash = erc7710TestTransaction().Hash().Hex()
	signer.sendErr = context.Canceled
	scheme := NewExactEvmScheme(signer, erc7710Config())
	_, err := scheme.Settle(ctx, payload, requirements, nil)
	assertSettlementPending(t, err, signer.sendTxHash)
	retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || !retry.Success || retry.Transaction != signer.sendTxHash || signer.sendCalls != 1 || signer.replayCalls.Load() != 1 {
		t.Fatalf("canceled send recovery: %+v %v", retry, err)
	}
}

type ambiguousERC7710Store struct {
	*InMemoryERC7710SettlementStore
	failed bool
}

func (s *ambiguousERC7710Store) Update(ctx context.Context, key string, generation uint64, record ERC7710SettlementRecord) error {
	if err := s.InMemoryERC7710SettlementStore.Update(ctx, key, generation, record); err != nil {
		return err
	}
	if !s.failed && record.Status == ERC7710SettlementBroadcast {
		s.failed = true
		return errors.New("commit acknowledgement lost")
	}
	return nil
}

func TestERC7710AmbiguousPersistenceRetainsRecoverableTransaction(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, erc7710Config())
	scheme.SetERC7710SettlementStore(&ambiguousERC7710Store{InMemoryERC7710SettlementStore: NewInMemoryERC7710SettlementStore()})
	_, err := scheme.Settle(context.Background(), payload, requirements, nil)
	assertSettleErr(t, err, ErrERC7710SettlementFailed, "")
	if signer.sendCalls != 0 {
		t.Fatal("broadcast after failed persistence acknowledgement")
	}
	retry, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err != nil || !retry.Success || signer.sendCalls != 0 || signer.replayCalls.Load() != 1 {
		t.Fatalf("ambiguous persistence recovery: %+v %v", retry, err)
	}
}
