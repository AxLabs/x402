package server_test

import (
	"context"
	"testing"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera"
	"github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/server"
	"github.com/x402-foundation/x402/go/v2/types"
)

func TestParsePriceAssetAmount(t *testing.T) {
	s := server.NewExactHederaScheme()
	got, err := s.ParsePrice(map[string]interface{}{
		"amount": "1000",
		"asset":  hedera.HederaTestnetUSDC,
	}, x402.Network(hedera.HederaTestnetCAIP2))
	if err != nil {
		t.Fatal(err)
	}
	if got.Amount != "1000" || got.Asset != hedera.HederaTestnetUSDC {
		t.Fatalf("got=%+v", got)
	}
}

func TestParsePriceMoneyDefaultUSDC(t *testing.T) {
	s := server.NewExactHederaScheme()
	got, err := s.ParsePrice(float64(0.10), x402.Network(hedera.HederaTestnetCAIP2))
	if err != nil {
		t.Fatal(err)
	}
	if got.Asset != hedera.HederaTestnetUSDC {
		t.Fatalf("asset=%s", got.Asset)
	}
	if got.Amount != "100000" { // 0.10 * 1e6
		t.Fatalf("amount=%s", got.Amount)
	}
}

func TestParsePriceInvalidAsset(t *testing.T) {
	s := server.NewExactHederaScheme()
	_, err := s.ParsePrice(map[string]interface{}{
		"amount": "1000",
		"asset":  "bad",
	}, x402.Network(hedera.HederaTestnetCAIP2))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEnhancePaymentRequirementsCopiesFeePayer(t *testing.T) {
	s := server.NewExactHederaScheme()
	req := types.PaymentRequirements{
		Scheme:  hedera.SchemeExact,
		Network: hedera.HederaTestnetCAIP2,
		Asset:   hedera.HBARAssetID,
		Amount:  "1",
		PayTo:   "0.0.1",
	}
	out, err := s.EnhancePaymentRequirements(context.Background(), req, types.SupportedKind{
		Extra: map[string]interface{}{"feePayer": "0.0.5001"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fee, _ := out.Extra["feePayer"].(string); fee != "0.0.5001" {
		t.Fatalf("extra=%v", out.Extra)
	}
}
