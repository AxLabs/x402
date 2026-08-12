package hedera

import (
	"bytes"
	"encoding/base64"
	"testing"

	sdkproto "github.com/hiero-ledger/hiero-sdk-go/v2/proto/sdk"
	"github.com/hiero-ledger/hiero-sdk-go/v2/proto/services"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"google.golang.org/protobuf/proto"
)

func TestAddOperatorSignaturesPreservesBodyBytes(t *testing.T) {
	client := hiero.ClientForTestnet()
	defer client.Close()

	payer, _ := hiero.AccountIDFromString("0.0.9001")
	payTo, _ := hiero.AccountIDFromString("0.0.7001")
	feePayer, _ := hiero.AccountIDFromString("0.0.5001")

	tx := hiero.NewTransferTransaction().
		AddHbarTransfer(payer, hiero.HbarFromTinybar(-50)).
		AddHbarTransfer(payTo, hiero.HbarFromTinybar(50)).
		SetTransactionID(hiero.TransactionIDGenerate(feePayer))
	frozen, err := tx.FreezeWith(client)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frozen.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	beforeBodies := collectBodyBytes(t, raw)

	opKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := addOperatorSignatures(raw, opKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed) == 0 {
		t.Fatal("expected signed transactions")
	}

	afterBodies := make([][]byte, 0, len(signed))
	for _, wire := range signed {
		st := &services.SignedTransaction{}
		if err := proto.Unmarshal(wire.SignedTransactionBytes, st); err != nil {
			t.Fatal(err)
		}
		afterBodies = append(afterBodies, append([]byte(nil), st.BodyBytes...))
		if len(st.SigMap.GetSigPair()) == 0 {
			t.Fatal("expected operator signature pair")
		}
	}
	if len(beforeBodies) != len(afterBodies) {
		t.Fatalf("body count %d != %d", len(beforeBodies), len(afterBodies))
	}
	for i := range beforeBodies {
		if !bytes.Equal(beforeBodies[i], afterBodies[i]) {
			t.Fatalf("BodyBytes changed at index %d", i)
		}
	}

	_ = base64.StdEncoding.EncodeToString(raw)
}

func collectBodyBytes(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	list := &sdkproto.TransactionList{}
	if err := proto.Unmarshal(raw, list); err != nil {
		single := &services.Transaction{}
		if err2 := proto.Unmarshal(raw, single); err2 != nil {
			t.Fatalf("decode: %v / %v", err, err2)
		}
		list.TransactionList = []*services.Transaction{single}
	}
	out := make([][]byte, 0, len(list.TransactionList))
	for _, wire := range list.TransactionList {
		st := &services.SignedTransaction{}
		if err := proto.Unmarshal(wire.SignedTransactionBytes, st); err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte(nil), st.BodyBytes...))
	}
	return out
}
