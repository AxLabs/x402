package server_test

import (
	"context"
	"errors"
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
	for _, price := range []x402.Price{float64(0.10), "$0.10"} {
		got, err := s.ParsePrice(price, x402.Network(hedera.HederaTestnetCAIP2))
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

func TestParsePriceCustomMoneyParser(t *testing.T) {
	s := server.NewExactHederaScheme().
		RegisterMoneyParser(func(amount float64, network x402.Network) (*x402.AssetAmount, error) {
			if amount != 2.5 || network != hedera.HederaTestnetCAIP2 {
				t.Fatalf("amount=%v network=%s", amount, network)
			}
			return &x402.AssetAmount{
				Asset:  "0.0.6001",
				Amount: "250",
			}, nil
		})
	got, err := s.ParsePrice("$2.50", x402.Network(hedera.HederaTestnetCAIP2))
	if err != nil || got.Asset != "0.0.6001" || got.Amount != "250" {
		t.Fatalf("got=%+v err=%v", got, err)
	}

	parserErr := errors.New("parser failed")
	s = server.NewExactHederaScheme().
		RegisterMoneyParser(func(float64, x402.Network) (*x402.AssetAmount, error) {
			return nil, parserErr
		})
	if _, err := s.ParsePrice("1", x402.Network(hedera.HederaTestnetCAIP2)); !errors.Is(err, parserErr) {
		t.Fatalf("expected parser error, got %v", err)
	}
}

func TestParsePriceConfiguredDefaultAsset(t *testing.T) {
	const network = hedera.HederaTestnetCAIP2
	s := server.NewExactHederaScheme(&hedera.ServerConfig{
		DefaultAssets: map[string]hedera.DefaultAssetConfig{
			network: {Asset: "0.0.6001", Decimals: 2},
		},
	})
	got, err := s.ParsePrice("1.25", x402.Network(network))
	if err != nil || got.Asset != "0.0.6001" || got.Amount != "125" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
