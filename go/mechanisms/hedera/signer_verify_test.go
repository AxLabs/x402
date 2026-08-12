package hedera

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
)

func TestParseMirrorAccountKey(t *testing.T) {
	ed, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseMirrorAccountKey(&mirrorAccountKey{
		Type: "ED25519",
		Key:  ed.PublicKey().StringRaw(),
	})
	if err != nil || key == nil {
		t.Fatalf("ed25519: %v %v", key, err)
	}

	ec, err := hiero.PrivateKeyGenerateEcdsa()
	if err != nil {
		t.Fatal(err)
	}
	key, err = parseMirrorAccountKey(&mirrorAccountKey{
		Type: "ECDSA_SECP256K1",
		Key:  ec.PublicKey().StringRaw(),
	})
	if err != nil || key == nil {
		t.Fatalf("ecdsa: %v %v", key, err)
	}

	list := hiero.NewKeyList().Add(ed.PublicKey()).Add(ec.PublicKey()).SetThreshold(1)
	protoBytes, err := hiero.KeyToBytes(list)
	if err != nil {
		t.Fatal(err)
	}
	key, err = parseMirrorAccountKey(&mirrorAccountKey{
		Type: "ProtobufEncoded",
		Key:  hex.EncodeToString(protoBytes),
	})
	if err != nil || key == nil {
		t.Fatalf("protobuf: %v %v", key, err)
	}

	key, err = parseMirrorAccountKey(nil)
	if err != nil || key != nil {
		t.Fatalf("nil key: %v %v", key, err)
	}
}

func TestVerifyPayerSignatureMirror(t *testing.T) {
	payerKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}

	client := hiero.ClientForTestnet()
	defer client.Close()
	feePayer, _ := hiero.AccountIDFromString("0.0.5001")
	payer, _ := hiero.AccountIDFromString("0.0.9001")
	payTo, _ := hiero.AccountIDFromString("0.0.7001")

	tx := hiero.NewTransferTransaction().
		AddHbarTransfer(payer, hiero.HbarFromTinybar(-50)).
		AddHbarTransfer(payTo, hiero.HbarFromTinybar(50)).
		SetTransactionID(hiero.TransactionIDGenerate(feePayer))
	frozen, err := tx.FreezeWith(client)
	if err != nil {
		t.Fatal(err)
	}
	signed := frozen.Sign(payerKey)
	raw, err := signed.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	txB64 := base64.StdEncoding.EncodeToString(raw)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/accounts/0.0.9001", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"key": map[string]string{
				"_type": "ED25519",
				"key":   payerKey.PublicKey().StringRaw(),
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	signer := &PrivateKeyFacilitatorSigner{
		operators:     nil,
		mirrorNodeURL: server.URL,
		http:          newMirrorHTTP(),
	}
	ok := signer.VerifyPayerSignature(context.Background(), "0.0.9001", txB64, HederaTestnetCAIP2)
	if !ok.OK {
		t.Fatalf("expected ok: %+v", ok)
	}

	muxWrong := http.NewServeMux()
	muxWrong.HandleFunc("/api/v1/accounts/0.0.9001", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"key": map[string]string{
				"_type": "ED25519",
				"key":   wrongKey.PublicKey().StringRaw(),
			},
		})
	})
	wrongServer := httptest.NewServer(muxWrong)
	defer wrongServer.Close()
	signer.mirrorNodeURL = wrongServer.URL
	bad := signer.VerifyPayerSignature(context.Background(), "0.0.9001", txB64, HederaTestnetCAIP2)
	if bad.OK || bad.Reason != "signature_invalid" {
		t.Fatalf("expected signature_invalid: %+v", bad)
	}
}

func TestParsePositiveAmount(t *testing.T) {
	n, err := ParsePositiveAmount("1000")
	if err != nil || n.String() != "1000" {
		t.Fatalf("%v %v", n, err)
	}
	if _, err := ParsePositiveAmount("0"); err == nil {
		t.Fatal("expected error for zero")
	}
	if _, err := ParsePositiveAmount("1.5"); err == nil {
		t.Fatal("expected error for decimal")
	}
	bigAmt := "9223372036854775808" // max int64 + 1
	n, err = ParsePositiveAmount(bigAmt)
	if err != nil {
		t.Fatal(err)
	}
	if n.IsInt64() {
		t.Fatal("expected non-int64")
	}
}
