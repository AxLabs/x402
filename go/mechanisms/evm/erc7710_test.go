package evm

import (
	"strings"
	"testing"
)

func validERC7710Map() map[string]interface{} {
	return map[string]interface{}{
		"delegationManager": "0x1111111111111111111111111111111111111111",
		"permissionContext": "0x1234",
		"delegator":         "0x2222222222222222222222222222222222222222",
	}
}

func TestERC7710PayloadFromMap(t *testing.T) {
	input := validERC7710Map()

	payload, err := ERC7710PayloadFromMap(input)
	if err != nil {
		t.Fatalf("ERC7710PayloadFromMap failed: %v", err)
	}
	if payload.DelegationManager != input["delegationManager"] ||
		payload.PermissionContext != input["permissionContext"] ||
		payload.Delegator != input["delegator"] {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if !IsERC7710Payload(payload.ToMap()) {
		t.Fatal("expected strict type guard to accept valid payload")
	}
}

func TestERC7710PayloadFromMapRejectsMalformedPayloads(t *testing.T) {
	valid := validERC7710Map()
	tests := map[string]func(map[string]interface{}){
		"missing field": func(data map[string]interface{}) { delete(data, "delegator") },
		"extra field":   func(data map[string]interface{}) { data["signature"] = "0x12" },
		"zero manager": func(data map[string]interface{}) {
			data["delegationManager"] = "0x" + strings.Repeat("0", 40)
		},
		"zero delegator": func(data map[string]interface{}) {
			data["delegator"] = "0x" + strings.Repeat("0", 40)
		},
		"invalid delegator":    func(data map[string]interface{}) { data["delegator"] = "not-an-address" },
		"empty context":        func(data map[string]interface{}) { data["permissionContext"] = "0x" },
		"odd context":          func(data map[string]interface{}) { data["permissionContext"] = "0x123" },
		"non-hex context":      func(data map[string]interface{}) { data["permissionContext"] = "0xzz" },
		"non-string manager":   func(data map[string]interface{}) { data["delegationManager"] = 1 },
		"non-string context":   func(data map[string]interface{}) { data["permissionContext"] = []byte{0x12} },
		"non-string delegator": func(data map[string]interface{}) { data["delegator"] = true },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			data := make(map[string]interface{}, len(valid))
			for key, value := range valid {
				data[key] = value
			}
			mutate(data)
			if _, err := ERC7710PayloadFromMap(data); err == nil {
				t.Fatal("expected validation error")
			}
			if IsERC7710Payload(data) {
				t.Fatal("type guard accepted malformed payload")
			}
		})
	}
}

func TestHasERC7710PayloadFieldsDetectsPartialPayloads(t *testing.T) {
	if HasERC7710PayloadFields(nil) {
		t.Fatal("nil map is not an ERC-7710 payload")
	}
	if HasERC7710PayloadFields(map[string]interface{}{"signature": "0x12"}) {
		t.Fatal("EIP-3009/Permit2 signature field must not route as ERC-7710")
	}
	for _, field := range []string{"delegationManager", "permissionContext", "delegator"} {
		if !HasERC7710PayloadFields(map[string]interface{}{field: "x"}) {
			t.Fatalf("expected %s to trigger ERC-7710 routing", field)
		}
	}
}

func TestERC7710PayloadRoundTripPreservesExactFields(t *testing.T) {
	input := validERC7710Map()
	payload, err := ERC7710PayloadFromMap(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ERC7710PayloadFromMap(payload.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DelegationManager != input["delegationManager"] ||
		parsed.PermissionContext != input["permissionContext"] ||
		parsed.Delegator != input["delegator"] {
		t.Fatalf("round-trip changed fields: %+v", parsed)
	}
}

func TestEIP3009AndPermit2PayloadsAreNotERC7710(t *testing.T) {
	eip3009 := (&ExactEIP3009Payload{
		Signature: "0x" + strings.Repeat("11", 65),
		Authorization: ExactEIP3009Authorization{
			From:        "0x1111111111111111111111111111111111111111",
			To:          "0x2222222222222222222222222222222222222222",
			Value:       "1",
			ValidAfter:  "0",
			ValidBefore: "1",
			Nonce:       "0x" + strings.Repeat("00", 32),
		},
	}).ToMap()
	permit2 := (&ExactPermit2Payload{
		Signature: "0x" + strings.Repeat("11", 65),
		Permit2Authorization: Permit2Authorization{
			From: "0x1111111111111111111111111111111111111111",
			Permitted: Permit2TokenPermissions{
				Token:  "0x2222222222222222222222222222222222222222",
				Amount: "1",
			},
			Spender:  X402ExactPermit2ProxyAddress,
			Nonce:    "1",
			Deadline: "1",
			Witness:  Permit2Witness{To: "0x3333333333333333333333333333333333333333", ValidAfter: "0"},
		},
	}).ToMap()

	for name, data := range map[string]map[string]interface{}{"eip3009": eip3009, "permit2": permit2} {
		if HasERC7710PayloadFields(data) || IsERC7710Payload(data) {
			t.Fatalf("%s payload routed as ERC-7710: %#v", name, data)
		}
	}
}
