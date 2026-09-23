package storage

import (
	"context"
	"testing"

	"github.com/Krutik090/scan-helper/internal/jobs"
)

func TestNoopSink_SavesNothingAndNeverFails(t *testing.T) {
	sink := NewNoop()
	job := jobs.Job{ID: "j1", Module: "subdomains", Status: jobs.StatusComplete}
	for name, write := range map[string]func(context.Context, jobs.Job) error{
		"Start":    sink.Start,
		"Progress": sink.Progress,
		"Save":     sink.Save,
	} {
		if err := write(context.Background(), job); err != nil {
			t.Fatalf("the no-op sink must never fail: %s: %v", name, err)
		}
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
