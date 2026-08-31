package hedera

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkproto "github.com/hiero-ledger/hiero-sdk-go/v2/proto/sdk"
	"github.com/hiero-ledger/hiero-sdk-go/v2/proto/services"
	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type testCryptoService struct {
	services.UnimplementedCryptoServiceServer
	code services.ResponseCodeEnum
}

func (s testCryptoService) CryptoTransfer(context.Context, *services.Transaction) (*services.TransactionResponse, error) {
	return &services.TransactionResponse{NodeTransactionPrecheckCode: s.code}, nil
}

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
	nodeID, err := nodeAccountIDFromSigned(signed[0])
	if err != nil || nodeID.String() == "" {
		t.Fatalf("node id=%s err=%v", nodeID.String(), err)
	}

	afterBodies := make([][]byte, 0, len(signed))
	for _, wire := range signed {
		st := &services.SignedTransaction{}
		if err := proto.Unmarshal(wire.GetSignedTransactionBytes(), st); err != nil {
			t.Fatal(err)
		}
		afterBodies = append(afterBodies, append([]byte(nil), st.GetBodyBytes()...))
		if len(st.GetSigMap().GetSigPair()) == 0 {
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

func TestRejectsMismatchedTransactionVariants(t *testing.T) {
	client := hiero.ClientForTestnet()
	defer client.Close()

	payer, _ := hiero.AccountIDFromString("0.0.9001")
	payTo, _ := hiero.AccountIDFromString("0.0.7001")
	feePayer, _ := hiero.AccountIDFromString("0.0.5001")
	payerKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := hiero.NewTransferTransaction().
		AddHbarTransfer(payer, hiero.HbarFromTinybar(-50)).
		AddHbarTransfer(payTo, hiero.HbarFromTinybar(50)).
		SetTransactionID(hiero.TransactionIDGenerate(feePayer)).
		FreezeWith(client)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frozen.Sign(payerKey).ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	list := &sdkproto.TransactionList{}
	if err := proto.Unmarshal(raw, list); err != nil {
		t.Fatal(err)
	}
	if len(list.GetTransactionList()) < 2 {
		t.Fatal("expected multiple node variants")
	}
	wire := list.GetTransactionList()[1]
	signed := &services.SignedTransaction{}
	if err := proto.Unmarshal(wire.GetSignedTransactionBytes(), signed); err != nil {
		t.Fatal(err)
	}
	body := &services.TransactionBody{}
	if err := proto.Unmarshal(signed.GetBodyBytes(), body); err != nil {
		t.Fatal(err)
	}
	amounts := body.GetCryptoTransfer().GetTransfers().GetAccountAmounts()
	if len(amounts) != 2 {
		t.Fatalf("account amounts=%d want 2", len(amounts))
	}
	amounts[0].Amount = -49
	amounts[1].Amount = 49
	signed.BodyBytes, err = proto.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signed.SigMap = &services.SignatureMap{
		SigPair: []*services.SignaturePair{
			signaturePairFor(payerKey.PublicKey(), payerKey.Sign(signed.GetBodyBytes())),
		},
	}
	wire.SignedTransactionBytes, err = proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = proto.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := hiero.TransactionFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !payerKey.PublicKey().VerifyTransaction(tx) {
		t.Fatal("expected payer signatures to be valid on every variant")
	}

	opKey, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := addOperatorSignatures(raw, opKey); err == nil {
		t.Fatal("expected mismatched variants to be rejected before co-signing")
	}
	if _, err := InspectTransaction(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("expected mismatched variants to be rejected during verification")
	}
}

func TestResolveNodeAddresses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("account.id") != "0.0.3" {
			http.Error(w, "unexpected node", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": []map[string]interface{}{{
				"node_account_id": "0.0.3",
				"service_endpoints": []map[string]interface{}{
					{"domain_name": "node.example", "port": 50211},
					{"domain_name": "ignored.example", "port": 50212},
				},
			}},
		})
	}))
	defer server.Close()
	signer := &PrivateKeyFacilitatorSigner{
		mirrorNodeURL: server.URL,
		http:          &mirrorHTTP{client: server.Client()},
	}
	addresses, err := signer.resolveNodeAddresses(
		context.Background(),
		HederaTestnetCAIP2,
		"0.0.3",
	)
	if err != nil || len(addresses) != 1 || addresses[0] != "node.example:50211" {
		t.Fatalf("addresses=%v err=%v", addresses, err)
	}
}

func TestSignAndSubmitTransactionRejectsInvalidInputs(t *testing.T) {
	key, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, _ := hiero.AccountIDFromString("0.0.5001")
	signer := &PrivateKeyFacilitatorSigner{
		operators: []operatorKey{{id: operatorID, key: key}},
		http:      newMirrorHTTP(),
	}

	if _, err := signer.SignAndSubmitTransaction(context.Background(), "", "0.0.5001", "hedera:previewnet"); err == nil {
		t.Fatal("expected unsupported network error")
	}
	if _, err := signer.SignAndSubmitTransaction(context.Background(), "", "0.0.9999", HederaTestnetCAIP2); err == nil {
		t.Fatal("expected unmanaged fee payer error")
	}
	if _, err := signer.SignAndSubmitTransaction(context.Background(), "%%%", "0.0.5001", HederaTestnetCAIP2); err == nil {
		t.Fatal("expected transaction decode error")
	}
}

func TestGRPCCryptoTransferPrecheck(t *testing.T) {
	tests := []struct {
		name    string
		code    services.ResponseCodeEnum
		wantErr bool
	}{
		{name: "accepted", code: services.ResponseCodeEnum_OK},
		{name: "rejected", code: services.ResponseCodeEnum_INVALID_SIGNATURE, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := grpc.NewServer()
			services.RegisterCryptoServiceServer(server, testCryptoService{code: tt.code})
			go func() {
				_ = server.Serve(listener)
			}()
			t.Cleanup(func() {
				server.Stop()
				_ = listener.Close()
			})

			err = grpcCryptoTransfer(context.Background(), listener.Addr().String(), &services.Transaction{})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestGRPCCryptoTransferTransportErrorIsAmbiguous(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	err = grpcCryptoTransfer(context.Background(), address, &services.Transaction{})
	var unknown *submissionOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected ambiguous transport error, got %T %v", err, err)
	}
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
	out := make([][]byte, 0, len(list.GetTransactionList()))
	for _, wire := range list.GetTransactionList() {
		st := &services.SignedTransaction{}
		if err := proto.Unmarshal(wire.GetSignedTransactionBytes(), st); err != nil {
			t.Fatal(err)
		}
		out = append(out, append([]byte(nil), st.GetBodyBytes()...))
	}
	return out
}
