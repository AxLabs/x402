# Hedera Mechanisms

Payment mechanism implementations for **Hedera** networks (CAIP-2 `hedera:mainnet` / `hedera:testnet`).

## Exact Payment Scheme

Fixed-amount payments using partially signed `TransferTransaction`s for **HBAR** (`0.0.0`, tinybars) or **HTS** fungible tokens (e.g. Circle USDC).

The facilitator is the **fee payer**: the client builds a transfer with `transactionId` owned by the facilitator account, signs as the debiting payer, and the facilitator co-signs and submits.

### Export Paths

#### Clients

```
github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/client
```

```go
signer, err := hedera.NewPrivateKeyClientSigner(accountID, privateKey, "hedera:testnet")
client := hederaclient.NewExactHederaScheme(signer)
```

#### Servers

```
github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/server
```

```go
server := hederaserver.NewExactHederaScheme()
// Copies feePayer from facilitator /supported into payment requirements.
```

#### Facilitators

```
github.com/x402-foundation/x402/go/v2/mechanisms/hedera/exact/facilitator
```

```go
facSigner, err := hedera.NewPrivateKeyFacilitatorSigner(hedera.SignerConfig{
	Operators: []hedera.OperatorCredentials{{
		AccountID:  "0.0.xxxx",
		PrivateKey: "0x...", // ECDSA hex preferred
	}},
})
scheme := hederafacil.NewExactHederaScheme(facSigner)
```

## Important implementation notes

1. **ECDSA key parsing** — 32-byte hex keys are treated as ECDSA secp256k1 (not ED25519). Prefer `0x`-prefixed ECDSA hex for EVM-compatible Hedera accounts.

2. **BodyBytes-preserving submit** — JS/TS clients encode AccountIDs with explicit shard/realm fields. The Go SDK `Execute` path remarsals bodies and invalidates those signatures. The default facilitator signer co-signs and submits at the protobuf/gRPC layer without remarsaling `BodyBytes`.

3. **Alias policy** — default `reject` (payTo must be an existing `0.0.x` entity id). Use `WithAliasPolicy("allow")` to relax.

4. **Mirror-backed verify** — `VerifyPayerSignature` and `PreflightTransfer` use the Mirror Node REST API (no operator-funded consensus queries).

5. **Settlement cache / HA** — the default `SettlementCache` is process-local with `SettlementTTL` expiry. Multi-replica facilitators must inject a shared `SettlementTracker` (or run a single settler); otherwise the same transaction ID can be settled twice.

## Supported networks

- `hedera:mainnet` — USDC `0.0.456858`
- `hedera:testnet` — USDC `0.0.429274`

Use `hedera:*` when registering with the facilitator.
