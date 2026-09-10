package facilitator

import (
	"context"
	"fmt"
	"sync"
	"time"

	x402 "github.com/x402-foundation/x402/go/v2"
)

type ERC7710SettlementStatus string

const (
	ERC7710SettlementProcessing ERC7710SettlementStatus = "processing"
	ERC7710SettlementBroadcast  ERC7710SettlementStatus = "broadcast"
	ERC7710SettlementSucceeded  ERC7710SettlementStatus = "succeeded"
	ERC7710SettlementTerminal   ERC7710SettlementStatus = "terminal"
)

type ERC7710SettlementRecord struct {
	Status       ERC7710SettlementStatus
	Transaction  string
	ErrorReason  string
	ErrorMessage string
}

// ERC7710SettlementStore provides atomic replay protection for ERC-7710
// permission contexts. Production implementations must be shared across
// facilitator replicas, atomically create the processing record in Acquire,
// and retain records for at least the permission context's validity window.
type ERC7710SettlementStore interface {
	Acquire(ctx context.Context, key string) (record ERC7710SettlementRecord, acquired bool, err error)
	Update(ctx context.Context, key string, record ERC7710SettlementRecord) error
	Delete(ctx context.Context, key string) error
}

type erc7710SettlementEntry struct {
	record   ERC7710SettlementRecord
	storedAt time.Time
}

type InMemoryERC7710SettlementStore struct {
	mu      sync.Mutex
	entries map[string]erc7710SettlementEntry
}

func NewInMemoryERC7710SettlementStore() *InMemoryERC7710SettlementStore {
	return &InMemoryERC7710SettlementStore{
		entries: make(map[string]erc7710SettlementEntry),
	}
}

func (s *InMemoryERC7710SettlementStore) Acquire(
	_ context.Context,
	key string,
) (ERC7710SettlementRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune()
	if entry, ok := s.entries[key]; ok {
		return entry.record, false, nil
	}
	record := ERC7710SettlementRecord{Status: ERC7710SettlementProcessing}
	s.entries[key] = erc7710SettlementEntry{record: record, storedAt: time.Now()}
	return record, true, nil
}

func (s *InMemoryERC7710SettlementStore) Update(
	_ context.Context,
	key string,
	record ERC7710SettlementRecord,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune()
	if _, ok := s.entries[key]; !ok {
		return fmt.Errorf("ERC-7710 settlement %q is not reserved", key)
	}
	s.entries[key] = erc7710SettlementEntry{record: record, storedAt: time.Now()}
	return nil
}

func (s *InMemoryERC7710SettlementStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, key)
	return nil
}

func (s *InMemoryERC7710SettlementStore) prune() {
	cutoff := time.Now().Add(-x402.PendingSettlementTTL)
	for key, entry := range s.entries {
		if entry.storedAt.Before(cutoff) {
			delete(s.entries, key)
		}
	}
}
