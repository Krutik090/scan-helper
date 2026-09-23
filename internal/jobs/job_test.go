package jobs

import (
	"errors"
	"sync"
	"testing"
)

func TestStore_LifecycleAndSnapshot(t *testing.T) {
	s := NewStore()
	s.Create(&Job{ID: "j1", Module: "subdomains", TenantID: "t1", Domain: "acme.test", Status: StatusRunning})

	s.SetCount("j1", 7)
	s.SetResult("j1", []string{"a", "b"})
	s.SetStatus("j1", StatusComplete)

	snap, ok := s.Snapshot("j1")
	if !ok {
		t.Fatal("job j1 should exist")
	}
	if snap.Count != 7 || snap.Status != StatusComplete {
		t.Fatalf("got %+v", snap)
	}
	if snap.CompletedAt == nil {
		t.Fatal("a terminal status must stamp CompletedAt")
	}
}

func TestStore_SetErrorRecordsMessage(t *testing.T) {
	s := NewStore()
	s.Create(&Job{ID: "j2", Status: StatusRunning})
	s.SetError("j2", errors.New("nmap exploded"))
	s.SetStatus("j2", StatusFailed)

	snap, _ := s.Snapshot("j2")
	if snap.Error != "nmap exploded" || snap.Status != StatusFailed {
		t.Fatalf("got %+v", snap)
	}
}

func TestStore_ListFilters(t *testing.T) {
	s := NewStore()
	s.Create(&Job{ID: "a", Module: "subdomains", TenantID: "t1"})
	s.Create(&Job{ID: "b", Module: "ports", TenantID: "t1"})
	s.Create(&Job{ID: "c", Module: "ports", TenantID: "t2"})

	if got := len(s.List("", "")); got != 3 {
		t.Errorf("unfiltered list = %d, want 3", got)
	}
	if got := len(s.List("t1", "")); got != 2 {
		t.Errorf("tenant t1 = %d, want 2", got)
	}
	if got := len(s.List("t1", "ports")); got != 1 {
		t.Errorf("tenant t1 + ports = %d, want 1", got)
	}
}

func TestStore_ConcurrentWritesAreSafe(t *testing.T) {
	s := NewStore()
	s.Create(&Job{ID: "hot", Status: StatusRunning})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.SetCount("hot", n)
			_, _ = s.Snapshot("hot")
		}(i)
	}
	wg.Wait()
	if _, ok := s.Snapshot("hot"); !ok {
		t.Fatal("job vanished under concurrent access")
	}
}
