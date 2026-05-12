// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package identitypolicy validates deployment and agent identity policy inputs
// that sit above the basic aTLS channel-binding checks.
package identitypolicy

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrMissingExpected = errors.New("identitypolicy: missing expected value")
	ErrMissingObserved = errors.New("identitypolicy: missing observed value")
	ErrMismatch        = errors.New("identitypolicy: value mismatch")
)

const (
	LayerL2B = "L2b"
	LayerL3  = "L3"
	LayerL4  = "L4"
	LayerL5  = "L5"
)

// Requirements selects which identity-policy layers must be enforced.
type Requirements struct {
	L2B bool `json:"l2b" yaml:"l2b"`
	L3  bool `json:"l3" yaml:"l3"`
	L4  bool `json:"l4" yaml:"l4"`
	L5  bool `json:"l5" yaml:"l5"`
}

// Values contains local expected values or observed peer values.
type Values struct {
	Service              string   `json:"service,omitempty" yaml:"service,omitempty"`
	Tenant               string   `json:"tenant,omitempty" yaml:"tenant,omitempty"`
	Deployment           string   `json:"deployment,omitempty" yaml:"deployment,omitempty"`
	Environment          string   `json:"environment,omitempty" yaml:"environment,omitempty"`
	Workload             string   `json:"workload,omitempty" yaml:"workload,omitempty"`
	Agent                string   `json:"agent,omitempty" yaml:"agent,omitempty"`
	AgentPublicKey       string   `json:"agent_public_key,omitempty" yaml:"agent_public_key,omitempty"`
	ComputationID        string   `json:"computation_id,omitempty" yaml:"computation_id,omitempty"`
	TaskID               string   `json:"task_id,omitempty" yaml:"task_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty" yaml:"thread_id,omitempty"`
	DelegationID         string   `json:"delegation_id,omitempty" yaml:"delegation_id,omitempty"`
	Scopes               []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Resources            []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty" yaml:"authorization_details,omitempty"`
}

// Policy separates local expected values from observed peer values.
type Policy struct {
	Require  Requirements `json:"require" yaml:"require"`
	Expected Values       `json:"expected" yaml:"expected"`
}

// Validate checks observed values against this policy.
func (p Policy) Validate(observed Values) error {
	return Validate(p, observed)
}

// ValidationError reports the exact layer and field that failed validation.
type ValidationError struct {
	Layer string
	Field string
	Err   error
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Layer, e.Field, e.Err)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// ValidationErrors reports all policy validation failures found in one pass.
type ValidationErrors []*ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("%d identity policy validation errors", len(e))
}

func (e ValidationErrors) Unwrap() []error {
	errs := make([]error, len(e))
	for i, err := range e {
		errs[i] = err
	}
	return errs
}

// Validate checks observed values against local expected policy values.
func Validate(policy Policy, observed Values) error {
	var errs ValidationErrors

	if policy.Require.L2B {
		if err := validateExactLayer(LayerL2B, policy.Expected, observed, []field{
			{"service", func(v Values) string { return v.Service }},
			{"tenant", func(v Values) string { return v.Tenant }},
			{"deployment", func(v Values) string { return v.Deployment }},
			{"environment", func(v Values) string { return v.Environment }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L3 {
		if err := validateExactLayer(LayerL3, policy.Expected, observed, []field{
			{"workload", func(v Values) string { return v.Workload }},
			{"agent", func(v Values) string { return v.Agent }},
			{"agent_public_key", func(v Values) string { return v.AgentPublicKey }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L4 {
		if err := validateExactLayer(LayerL4, policy.Expected, observed, []field{
			{"computation_id", func(v Values) string { return v.ComputationID }},
			{"task_id", func(v Values) string { return v.TaskID }},
			{"thread_id", func(v Values) string { return v.ThreadID }},
			{"delegation_id", func(v Values) string { return v.DelegationID }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if policy.Require.L5 {
		if err := validateL5(policy.Expected, observed); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

type field struct {
	name string
	get  func(Values) string
}

func validateExactLayer(layer string, expected, observed Values, fields []field) error {
	var errs ValidationErrors
	hasExpected := false
	for _, f := range fields {
		want := f.get(expected)
		if isEmpty(want) {
			continue
		}
		hasExpected = true
		got := f.get(observed)
		if isEmpty(got) {
			errs = append(errs, validationError(layer, f.name, ErrMissingObserved))
			continue
		}
		if got != want {
			errs = append(errs, validationError(layer, f.name, ErrMismatch))
		}
	}
	if !hasExpected {
		return validationError(layer, "*", ErrMissingExpected)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateL5(expected, observed Values) error {
	var errs ValidationErrors
	hasExpected := false
	if len(expected.Scopes) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, "scopes", expected.Scopes, observed.Scopes); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.Resources) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, "resources", expected.Resources, observed.Resources); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if len(expected.AuthorizationDetails) > 0 {
		hasExpected = true
		if err := requireContainsAll(LayerL5, "authorization_details", expected.AuthorizationDetails, observed.AuthorizationDetails); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if !hasExpected {
		return validationError(LayerL5, "*", ErrMissingExpected)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func requireContainsAll(layer, fieldName string, expected, observed []string) error {
	seen := make(map[string]struct{}, len(observed))
	for _, value := range observed {
		if isEmpty(value) {
			continue
		}
		seen[value] = struct{}{}
	}
	if len(seen) == 0 {
		return validationError(layer, fieldName, ErrMissingObserved)
	}
	for _, value := range expected {
		if isEmpty(value) {
			return validationError(layer, fieldName, ErrMissingExpected)
		}
		if _, ok := seen[value]; !ok {
			return validationError(layer, fieldName, ErrMismatch)
		}
	}
	return nil
}

func appendValidationErrors(errs ValidationErrors, err error) ValidationErrors {
	if err == nil {
		return errs
	}
	var validationErrors ValidationErrors
	if errors.As(err, &validationErrors) {
		return append(errs, validationErrors...)
	}
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return append(errs, validationErr)
	}
	return append(errs, validationError("*", "*", err))
}

func validationError(layer, field string, err error) *ValidationError {
	return &ValidationError{
		Layer: layer,
		Field: field,
		Err:   err,
	}
}

func isEmpty(value string) bool {
	return strings.TrimSpace(value) == ""
}
