package facilitator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

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
	simulationErr error
	sendErr       error
	simulateCalls int
	sendCalls     int
	from          string
	to            string
	data          []byte
	gasLimit      uint64
	chainID       *big.Int
}

func (s *erc7710FacilitatorSigner) GetAddresses() []string {
	return []string{testERC7710Caller}
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
		return "", s.sendErr
	}
	return "0x" + strings.Repeat("77", 32), nil
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
	}}
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
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{ERC7710GasLimit: testERC7710GasLimit})

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
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.simulationErr = fmt.Errorf("execution reverted: caveat violation")
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{ERC7710GasLimit: testERC7710GasLimit})

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710SimulationFailed)
}

func TestVerifyERC7710RequiresConfiguredGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), nil)

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710GasLimitRequired)
}

func TestVerifyERC7710RejectsSignerNetworkMismatch(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	signer.chainID = big.NewInt(1)
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{ERC7710GasLimit: testERC7710GasLimit})

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrNetworkMismatch)
}

func TestVerifyERC7710RejectsPermissionContextOutsideGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permissionContext"] = "0x" + strings.Repeat("00", 130_000)
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{ERC7710GasLimit: testERC7710GasLimit})

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrERC7710CalldataExceedsGasLimit)
	if signer.simulateCalls != 0 {
		t.Fatal("oversized permissionContext reached simulation")
	}
}

func TestVerifyRoutesMalformedERC7710BeforePermit2(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	payload.Payload["permit2Authorization"] = map[string]interface{}{}
	scheme := NewExactEvmScheme(newERC7710FacilitatorSigner(), &ExactEvmSchemeConfig{ERC7710GasLimit: testERC7710GasLimit})

	_, err := scheme.Verify(context.Background(), payload, requirements, nil)
	assertERC7710VerifyReason(t, err, ErrInvalidPayload)
}

func TestSettleERC7710SimulatesWhenConfiguredAndSendsWithGasLimit(t *testing.T) {
	payload, requirements, _ := erc7710Fixture()
	signer := newERC7710FacilitatorSigner()
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{
		ERC7710GasLimit:  testERC7710GasLimit,
		SimulateInSettle: true,
	})

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
