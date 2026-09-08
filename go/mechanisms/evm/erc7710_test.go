package evm

import (
	"strings"
	"testing"
)

func TestERC7710PayloadFromMap(t *testing.T) {
	input := map[string]interface{}{
		"delegationManager": "0x1111111111111111111111111111111111111111",
		"permissionContext": "0x1234",
		"delegator":         "0x2222222222222222222222222222222222222222",
	}

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
	valid := map[string]interface{}{
		"delegationManager": "0x1111111111111111111111111111111111111111",
		"permissionContext": "0x1234",
		"delegator":         "0x2222222222222222222222222222222222222222",
	}
	tests := map[string]func(map[string]interface{}){
		"missing field": func(data map[string]interface{}) { delete(data, "delegator") },
		"extra field":   func(data map[string]interface{}) { data["signature"] = "0x12" },
		"zero manager": func(data map[string]interface{}) {
			data["delegationManager"] = "0x" + strings.Repeat("0", 40)
		},
		"invalid delegator": func(data map[string]interface{}) { data["delegator"] = "not-an-address" },
		"empty context":     func(data map[string]interface{}) { data["permissionContext"] = "0x" },
		"odd context":       func(data map[string]interface{}) { data["permissionContext"] = "0x123" },
		"non-hex context":   func(data map[string]interface{}) { data["permissionContext"] = "0xzz" },
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
