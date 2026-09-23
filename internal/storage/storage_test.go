package storage

import (
	"context"
	"testing"

	"github.com/Krutik090/scan-helper/internal/jobs"
)

func TestNoopSink_SavesNothingAndNeverFails(t *testing.T) {
	sink := NewNoop()
	err := sink.Save(context.Background(), jobs.Job{ID: "j1", Module: "subdomains", Status: jobs.StatusComplete})
	if err != nil {
		t.Fatalf("the no-op sink must never fail: %v", err)
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNoopTargetLister_ReturnsTheDomainItself(t *testing.T) {
	targets, err := NoopTargetLister{}.Targets(context.Background(), "t1", "acme.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "acme.test" {
		t.Fatalf("got %+v, want just the domain — nothing is stored in api_response mode", targets)
	}
}
