package client_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	sdkproto "github.com/hiero-ledger/hiero-sdk-go/v2/proto/sdk"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/client"
	"github.com/x402-foundation/x402/go/v2/types"
	"google.golang.org/protobuf/proto"
)

type fakeClientSigner struct {
	accountID string
	txB64     string
	err       error
}

func (f *fakeClientSigner) AccountID() string { return f.accountID }
func (f *fakeClientSigner) CreatePartiallySignedTransferTransaction(
	_ context.Context, _ types.PaymentRequirements,
) (string, error) {
	return f.txB64, f.err
}

func TestClientCreatePaymentPayload(t *testing.T) {
	tx := base64.StdEncoding.EncodeToString([]byte("fake-tx"))
	scheme := client.NewExactHederaScheme(&fakeClientSigner{
		accountID: "0.0.9001",
		txB64:     tx,
	})
	req := types.PaymentRequirements{
		Scheme:            hedera.SchemeExact,
		Network:           hedera.HederaTestnetCAIP2,
		Asset:             hedera.HBARAssetID,
		Amount:            "50",
		PayTo:             "0.0.7001",
		MaxTimeoutSeconds: 180,
		Extra:             map[string]interface{}{"feePayer": "0.0.5001"},
	}
	payload, err := scheme.CreatePaymentPayload(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if payload.X402Version != 2 {
		t.Fatalf("version=%d", payload.X402Version)
	}
	got, _ := payload.Payload["transaction"].(string)
	if got != tx {
		t.Fatalf("transaction=%q", got)
	}
	if payload.Accepted.Extra["feePayer"] != "0.0.5001" {
		t.Fatalf("accepted=%+v", payload.Accepted)
	}
}

func TestClientRequiresFeePayer(t *testing.T) {
	scheme := client.NewExactHederaScheme(&fakeClientSigner{accountID: "0.0.9001"})
	_, err := scheme.CreatePaymentPayload(context.Background(), types.PaymentRequirements{
		Scheme:  hedera.SchemeExact,
		Network: hedera.HederaTestnetCAIP2,
	})
	if err == nil {
		t.Fatal("expected missing feePayer error")
	}
}

func TestClientBuildRealPartialTransfer(t *testing.T) {
	// Deterministic ED25519 DER key (SDK test vector style).
	const ed25519DER = "302e020100300506032b657004220420a869f4c6191b9c8c99933e7f6b6611711737e4b1a1a5a4cb5370e719a1f6df98"
	signer, err := hedera.NewPrivateKeyClientSigner("0.0.9001", ed25519DER, hedera.HederaTestnetCAIP2)
	if err != nil {
		t.Fatal(err)
	}
	scheme := client.NewExactHederaScheme(signer)
	req := types.PaymentRequirements{
		Scheme:            hedera.SchemeExact,
		Network:           hedera.HederaTestnetCAIP2,
		Asset:             hedera.HBARAssetID,
		Amount:            "50",
		PayTo:             "0.0.7001",
		MaxTimeoutSeconds: 180,
		Extra:             map[string]interface{}{"feePayer": "0.0.5001"},
	}
	payload, err := scheme.CreatePaymentPayload(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	txB64, _ := payload.Payload["transaction"].(string)
	inspected, err := hedera.InspectTransaction(txB64)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.TransactionType != "TransferTransaction" {
		t.Fatalf("type=%s", inspected.TransactionType)
	}
	if inspected.TransactionIDAccount != "0.0.5001" {
		t.Fatalf("fee payer account=%s", inspected.TransactionIDAccount)
	}
}

func TestClientLimitsNodeVariantsAndPaymentHeaderSize(t *testing.T) {
	// Deterministic ED25519 DER key (SDK test vector style).
	const ed25519DER = "302e020100300506032b657004220420a869f4c6191b9c8c99933e7f6b6611711737e4b1a1a5a4cb5370e719a1f6df98"
	signer, err := hedera.NewPrivateKeyClientSigner("0.0.9001", ed25519DER, hedera.HederaMainnetCAIP2)
	if err != nil {
		t.Fatal(err)
	}
	scheme := client.NewExactHederaScheme(signer)
	req := types.PaymentRequirements{
		Scheme:            hedera.SchemeExact,
		Network:           hedera.HederaMainnetCAIP2,
		Asset:             hedera.HederaMainnetUSDC,
		Amount:            "100000",
		PayTo:             "0.0.10787907",
		MaxTimeoutSeconds: 300,
		Extra:             map[string]interface{}{"feePayer": "0.0.10789914"},
	}
	payload, err := scheme.CreatePaymentPayload(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	txB64, _ := payload.Payload["transaction"].(string)
	raw, err := base64.StdEncoding.DecodeString(txB64)
	if err != nil {
		t.Fatal(err)
	}
	var txList sdkproto.TransactionList
	if err := proto.Unmarshal(raw, &txList); err != nil {
		t.Fatal(err)
	}
	if got := len(txList.TransactionList); got != 3 {
		t.Fatalf("node transaction variants=%d, want 3", got)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.StdEncoding.EncodeToString(payloadJSON)
	if len(header) >= 4096 {
		t.Fatalf("PAYMENT-SIGNATURE length=%d, want less than 4096", len(header))
	}
}
