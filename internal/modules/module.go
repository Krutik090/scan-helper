// Package modules defines the contract every scan module implements and
// the registry the API and setup tooling look modules up through.
//
// A module must never import net/http or the Mongo driver. It takes
// typed parameters and a context, and returns its raw findings. Two
// consequences that matter:
//
//   - Adding a module is a new package plus one Register call. Nothing
//     in the API or storage layer changes.
//   - Run returns findings that have NOT been merged with any previously
//     stored state. Merging is the storage layer's job, because only it
//     knows whether prior state exists at all (in api_response mode
//     there is none). Each module exports a pure Merge function for the
//     storage layer to call.
package modules

import "context"

// ToolRequirement names an external binary a module needs, and the
// configured path to look for it at. The /health endpoint and the setup
// script both read these, so there is one source of truth for "what does
// this module need installed".
type ToolRequirement struct {
	Name    string
	BinPath string
}

// RunParams is what every module's Run receives. A module ignores the
// fields it doesn't need.
type RunParams struct {
	JobID    string
	TenantID string
	Domain   string
}

// Module is the contract. onProgress may be nil; when non-nil a module
// should call it as findings accumulate so a poller sees movement.
type Module interface {
	Name() string
	RequiredTools() []ToolRequirement
	Run(ctx context.Context, params RunParams, onProgress func(count int)) (any, error)
}
