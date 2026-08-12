package facilitator_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"

	hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/facilitator"
	"github.com/x402-foundation/x402/go/v2/types"
)

type mockSigner struct {
	addresses []string
	submitTx  string
	submitErr error
	resolve   hedera.AccountResolution
	resolveEr error
	sig       hedera.SignatureCheck
	preflight hedera.SignatureCheck
}

func (m *mockSigner) GetAddresses(context.Context, string) []string { return m.addresses }
func (m *mockSigner) SignAndSubmitTransaction(context.Context, string, string, string) (string, error) {
	return m.submitTx, m.submitErr
}
func (m *mockSigner) VerifyPayerSignature(context.Context, string, string, string) hedera.SignatureCheck {
	return m.sig
}
func (m *mockSigner) PreflightTransfer(context.Context, string, string, string, string, string) hedera.SignatureCheck {
	return m.preflight
}
func (m *mockSigner) ResolveAccount(context.Context, string, string) (hedera.AccountResolution, error) {
	return m.resolve, m.resolveEr
}

func newMockSigner() *mockSigner {
	return &mockSigner{
		addresses: []string{"0.0.5001"},
		submitTx:  "0.0.5001@1700000001.000000000",
		resolve:   hedera.AccountResolution{Exists: true, IsAlias: false},
		sig:       hedera.SignatureCheck{OK: true},
		preflight: hedera.SignatureCheck{OK: true},
	}
}

func baseRequirements() types.PaymentRequirements {
	return types.PaymentRequirements{
		Scheme:            hedera.SchemeExact,
		Network:           hedera.HederaTestnetCAIP2,
		Asset:             "0.0.6001",
		Amount:            "1000",
		PayTo:             "0.0.7001",
		MaxTimeoutSeconds: 180,
		Extra:             map[string]interface{}{"feePayer": "0.0.5001"},
	}
}

func basePayload(req types.PaymentRequirements, txB64 string) types.PaymentPayload {
	return types.PaymentPayload{
		X402Version: 2,
		Resource: &types.ResourceInfo{
			URL:         "https://example.com",
			Description: "resource",
			MimeType:     "application/json",
		},
		Accepted: req,
		Payload:  map[string]interface{}{"transaction": txB64},
	}
}

func createTransferB64(t *testing.T, feePayer, payer, payTo, asset, amount string) string {
	t.Helper()
	client := hiero.ClientForTestnet()
	defer client.Close()

	feeID, err := hiero.AccountIDFromString(feePayer)
	if err != nil {
		t.Fatal(err)
	}
	payerID, err := hiero.AccountIDFromString(payer)
	if err != nil {
		t.Fatal(err)
	}
	payToID, err := hiero.AccountIDFromString(payTo)
	if err != nil {
		t.Fatal(err)
	}
	amt, err := strconv.ParseInt(amount, 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	tx := hiero.NewTransferTransaction()
	if asset == hedera.HBARAssetID {
		tx.AddHbarTransfer(payerID, hiero.HbarFromTinybar(-amt))
		tx.AddHbarTransfer(payToID, hiero.HbarFromTinybar(amt))
	} else {
		tokenID, err := hiero.TokenIDFromString(asset)
		if err != nil {
			t.Fatal(err)
		}
		tx.AddTokenTransfer(tokenID, payerID, -amt)
		tx.AddTokenTransfer(tokenID, payToID, amt)
	}
	tx.SetTransactionID(hiero.TransactionIDGenerate(feeID))
	frozen, err := tx.FreezeWith(client)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frozen.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func createTopicB64(t *testing.T, feePayer string) string {
	t.Helper()
	client := hiero.ClientForTestnet()
	defer client.Close()
	feeID, err := hiero.AccountIDFromString(feePayer)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hiero.PrivateKeyGenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	tx := hiero.NewTopicCreateTransaction().
		SetTransactionID(hiero.TransactionIDGenerate(feeID)).
		SetTopicMemo("x402-non-transfer").
		SetSubmitKey(key.PublicKey())
	frozen, err := tx.FreezeWith(client)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := frozen.ToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func verifyReason(t *testing.T, err error) string {
	t.Helper()
	var ve *x402.VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected VerifyError, got %T %v", err, err)
	}
	return ve.InvalidReason
}

func TestFacilitatorVerifyValid(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()
	payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))

	resp, err := scheme.Verify(context.Background(), payload, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsValid || resp.Payer != "0.0.9001" {
		t.Fatalf("resp=%+v", resp)
	}
}

func TestFacilitatorRejectsAssetMismatch(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()
	payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.1234", "1000"))
	_, err := scheme.Verify(context.Background(), payload, req, nil)
	if verifyReason(t, err) != facilitator.ErrAssetMismatch {
		t.Fatalf("reason=%s", verifyReason(t, err))
	}
}

func TestFacilitatorAliasPolicy(t *testing.T) {
	signer := newMockSigner()
	signer.resolve = hedera.AccountResolution{Exists: false, IsAlias: true}
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()
	payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))
	_, err := scheme.Verify(context.Background(), payload, req, nil)
	if verifyReason(t, err) != facilitator.ErrPayToAliasNotAllowed {
		t.Fatalf("reason=%s", verifyReason(t, err))
	}

	scheme.WithAliasPolicy(hedera.AliasPolicyAllow)
	resp, err := scheme.Verify(context.Background(), payload, req, nil)
	if err != nil || !resp.IsValid {
		t.Fatalf("allow aliases: %v %+v", err, resp)
	}
}

func TestFacilitatorUndecodable(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()
	payload := basePayload(req, "not-a-valid-hedera-transaction")
	_, err := scheme.Verify(context.Background(), payload, req, nil)
	if verifyReason(t, err) != facilitator.ErrTransactionDecode {
		t.Fatalf("reason=%s", verifyReason(t, err))
	}
}

func TestFacilitatorSettle(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()
	payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))
	settled, err := scheme.Settle(context.Background(), payload, req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !settled.Success || settled.Transaction != signer.submitTx {
		t.Fatalf("settled=%+v", settled)
	}
}

func TestFacilitatorReasonMatrix(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	req := baseRequirements()

	t.Run("unsupported_scheme", func(t *testing.T) {
		bad := req
		bad.Scheme = "other"
		payload := basePayload(bad, "")
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrUnsupportedScheme {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("accepted_mismatch", func(t *testing.T) {
		payload := basePayload(req, "")
		payload.Accepted.Amount = "999"
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrAcceptedMismatch {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("network_mismatch", func(t *testing.T) {
		payload := basePayload(req, "")
		payload.Accepted.Network = hedera.HederaMainnetCAIP2
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrNetworkMismatch {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("invalid_asset", func(t *testing.T) {
		bad := req
		bad.Asset = "invalid"
		payload := basePayload(bad, "")
		_, err := scheme.Verify(context.Background(), payload, bad, nil)
		if verifyReason(t, err) != facilitator.ErrInvalidAsset {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("invalid_amount", func(t *testing.T) {
		bad := req
		bad.Amount = "1.23"
		payload := basePayload(bad, "")
		_, err := scheme.Verify(context.Background(), payload, bad, nil)
		if verifyReason(t, err) != facilitator.ErrInvalidAmount {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("missing_fee_payer", func(t *testing.T) {
		bad := req
		bad.Extra = map[string]interface{}{}
		payload := basePayload(bad, "")
		_, err := scheme.Verify(context.Background(), payload, bad, nil)
		if verifyReason(t, err) != facilitator.ErrMissingFeePayer {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("fee_payer_not_managed", func(t *testing.T) {
		s := newMockSigner()
		s.addresses = []string{"0.0.9999"}
		_, err := facilitator.NewExactHederaScheme(s).Verify(context.Background(), basePayload(req, ""), req, nil)
		if verifyReason(t, err) != facilitator.ErrFeePayerNotManaged {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("fee_payer_mismatch", func(t *testing.T) {
		payload := basePayload(req, createTransferB64(t, "0.0.5002", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrFeePayerMismatch {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("non_transfer", func(t *testing.T) {
		payload := basePayload(req, createTopicB64(t, "0.0.5001"))
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrNonTransferOps {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("signature_invalid", func(t *testing.T) {
		s := newMockSigner()
		s.sig = hedera.SignatureCheck{OK: false, Reason: "bad_sig", Message: "nope"}
		payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))
		_, err := facilitator.NewExactHederaScheme(s).Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrSignatureInvalid {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("preflight_failed", func(t *testing.T) {
		s := newMockSigner()
		s.preflight = hedera.SignatureCheck{OK: false, Reason: "insufficient_balance", Message: "low"}
		payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000"))
		_, err := facilitator.NewExactHederaScheme(s).Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrPreflightFailed {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("amount_mismatch", func(t *testing.T) {
		payload := basePayload(req, createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "500"))
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrAmountMismatch {
			t.Fatal(verifyReason(t, err))
		}
	})

	t.Run("fee_payer_debit_hbar", func(t *testing.T) {
		hbarReq := req
		hbarReq.Asset = hedera.HBARAssetID
		hbarReq.Amount = "50"
		payload := basePayload(hbarReq, createTransferB64(t, "0.0.5001", "0.0.5001", "0.0.7001", hedera.HBARAssetID, "50"))
		_, err := scheme.Verify(context.Background(), payload, hbarReq, nil)
		reason := verifyReason(t, err)
		if reason != facilitator.ErrFeePayerTransferringHbar && reason != facilitator.ErrFeePayerTransferringFunds {
			t.Fatalf("reason=%s", reason)
		}
	})

	t.Run("replay", func(t *testing.T) {
		cache := hedera.NewSettlementCache()
		s := newMockSigner()
		scheme := facilitator.NewExactHederaScheme(s, cache)
		tx := createTransferB64(t, "0.0.5001", "0.0.9001", "0.0.7001", "0.0.6001", "1000")
		payload := basePayload(req, tx)
		if _, err := scheme.Settle(context.Background(), payload, req, nil); err != nil {
			t.Fatal(err)
		}
		_, err := scheme.Verify(context.Background(), payload, req, nil)
		if verifyReason(t, err) != facilitator.ErrReplay {
			t.Fatal(verifyReason(t, err))
		}
	})
}

func TestFacilitatorGetExtraAndSigners(t *testing.T) {
	signer := newMockSigner()
	scheme := facilitator.NewExactHederaScheme(signer)
	if scheme.Scheme() != hedera.SchemeExact || scheme.CaipFamily() != "hedera:*" {
		t.Fatal("scheme identity")
	}
	extra := scheme.GetExtra(x402.Network(hedera.HederaTestnetCAIP2))
	if fee, _ := extra["feePayer"].(string); fee != "0.0.5001" {
		t.Fatalf("extra=%v", extra)
	}
	signers := scheme.GetSigners(x402.Network(hedera.HederaTestnetCAIP2))
	if len(signers) != 1 || signers[0] != "0.0.5001" {
		t.Fatalf("signers=%v", signers)
	}
}
