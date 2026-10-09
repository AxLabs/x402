package facilitator

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"
)

type ERC7710SettlementStatus string

const (
	ERC7710SettlementProcessing ERC7710SettlementStatus = "processing"
	ERC7710SettlementBroadcast  ERC7710SettlementStatus = "broadcast"
	ERC7710SettlementSucceeded  ERC7710SettlementStatus = "succeeded"
	ERC7710SettlementTerminal   ERC7710SettlementStatus = "terminal"
)

type ERC7710SettlementRecord struct {
	Fingerprint       string
	SignedTransaction []byte
	LeaseExpiresAt    time.Time
	Status            ERC7710SettlementStatus
	Transaction       string
	ErrorReason       string
	ErrorMessage      string
}

// NewERC7710SettlementRecord reserves preparation for one minute. An expired
// preparation can be reclaimed; persisted transactions must never expire.
func NewERC7710SettlementRecord() ERC7710SettlementRecord {
	return ERC7710SettlementRecord{Status: ERC7710SettlementProcessing, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func (r ERC7710SettlementRecord) ProcessingExpired() bool {
	return r.Status == ERC7710SettlementProcessing && !r.LeaseExpiresAt.IsZero() && !time.Now().Before(r.LeaseExpiresAt)
}

// ERC7710SettlementStore provides atomic replay protection for ERC-7710
// permission contexts. Production implementations must be shared across
// facilitator replicas, fence updates by generation, and retain records until
// the permission context can no longer authorize a transfer. Acquire may replace
// expired processing claims only. Update must preserve immutable bindings using
// MergeERC7710SettlementRecord. Delete must reject records containing a transaction.
type ERC7710SettlementStore interface {
	Acquire(ctx context.Context, key string) (record ERC7710SettlementRecord, generation uint64, acquired bool, err error)
	Get(ctx context.Context, key string) (record ERC7710SettlementRecord, generation uint64, found bool, err error)
	Update(ctx context.Context, key string, generation uint64, record ERC7710SettlementRecord) error
	Delete(ctx context.Context, key string, generation uint64) error
}

type erc7710SettlementEntry struct {
	record     ERC7710SettlementRecord
	generation uint64
}

type InMemoryERC7710SettlementStore struct {
	mu             sync.Mutex
	entries        map[string]erc7710SettlementEntry
	nextGeneration uint64
}

// NewInMemoryERC7710SettlementStore creates a process-local store that retains
// every claim for the process lifetime.
func NewInMemoryERC7710SettlementStore() *InMemoryERC7710SettlementStore {
	return &InMemoryERC7710SettlementStore{
		entries: make(map[string]erc7710SettlementEntry),
	}
}

func (s *InMemoryERC7710SettlementStore) Acquire(
	_ context.Context,
	key string,
) (ERC7710SettlementRecord, uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.entries[key]; ok && !entry.record.ProcessingExpired() {
		return entry.record, entry.generation, false, nil
	}
	s.nextGeneration++
	if s.nextGeneration == 0 {
		s.nextGeneration++
	}
	record := NewERC7710SettlementRecord()
	entry := erc7710SettlementEntry{record: record, generation: s.nextGeneration}
	s.entries[key] = entry
	return record, entry.generation, true, nil
}

func (s *InMemoryERC7710SettlementStore) Get(
	_ context.Context,
	key string,
) (ERC7710SettlementRecord, uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return ERC7710SettlementRecord{}, 0, false, nil
	}
	return entry.record, entry.generation, true, nil
}

func (s *InMemoryERC7710SettlementStore) Update(
	_ context.Context,
	key string,
	generation uint64,
	record ERC7710SettlementRecord,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.entryForGeneration(key, generation)
	if err != nil {
		return err
	}
	merged, err := MergeERC7710SettlementRecord(entry.record, record)
	if err != nil {
		return err
	}
	entry.record = merged
	s.entries[key] = entry
	return nil
}

func (s *InMemoryERC7710SettlementStore) Delete(
	_ context.Context,
	key string,
	generation uint64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[key]; !ok {
		return nil
	}
	entry, err := s.entryForGeneration(key, generation)
	if err != nil {
		return err
	}
	if entry.record.Status != ERC7710SettlementProcessing || entry.record.Transaction != "" || len(entry.record.SignedTransaction) != 0 {
		return fmt.Errorf("cannot delete a persisted transaction")
	}
	delete(s.entries, key)
	return nil
}

func (s *InMemoryERC7710SettlementStore) entryForGeneration(
	key string,
	generation uint64,
) (erc7710SettlementEntry, error) {
	entry, ok := s.entries[key]
	if !ok {
		return erc7710SettlementEntry{}, fmt.Errorf("ERC-7710 settlement %q is not reserved", key)
	}
	if entry.generation != generation {
		return erc7710SettlementEntry{}, fmt.Errorf("ERC-7710 settlement %q reservation changed", key)
	}
	return entry, nil
}

// MergeERC7710SettlementRecord keeps the request and signed transaction bound
// across status updates, including updates from concurrent receipt waiters.
func MergeERC7710SettlementRecord(current, next ERC7710SettlementRecord) (ERC7710SettlementRecord, error) {
	if current.Fingerprint != "" {
		if next.Fingerprint != "" && next.Fingerprint != current.Fingerprint {
			return next, fmt.Errorf("payment fingerprint changed")
		}
		next.Fingerprint = current.Fingerprint
	}
	if current.Transaction != "" {
		if next.Transaction != "" && next.Transaction != current.Transaction {
			return next, fmt.Errorf("settlement transaction changed")
		}
		next.Transaction = current.Transaction
	}
	if len(current.SignedTransaction) > 0 {
		if len(next.SignedTransaction) > 0 && !bytes.Equal(next.SignedTransaction, current.SignedTransaction) {
			return next, fmt.Errorf("signed transaction changed")
		}
		next.SignedTransaction = append([]byte(nil), current.SignedTransaction...)
	}
	next.SignedTransaction = append([]byte(nil), next.SignedTransaction...)
	return next, nil
}
