// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"time"
)

var (
	ErrUnauthorizedBindingKey = errors.New("identitypolicy: unauthorized session binding key")
)

const (
	LayerIdentityGrant  = "identity_grant"
	LayerSessionBinding = "session_binding"

	FieldIssuer          = "issuer"
	FieldAudience        = "aud"
	FieldGrantHash       = "grant_hash"
	FieldSignerKey       = "signer_key"
	FieldConfirmationKey = "confirmation_key"
)

// VerifiedGrant is an already-authenticated identity grant.
//
// This type is not a wire-token format and does not verify signatures. Callers
// should construct it only after authenticating a deployment-specific grant
// from a trusted manager or policy authority.
type VerifiedGrant struct {
	Issuer                 string
	Audience               string
	GrantHash              string
	Values                 Values
	ConfirmationKey        string
	AuthorizedEndpointKeys []string
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

// VerifiedSessionBindingStatement is an already-verified holder-of-key proof
// that binds a grant to the accepted aTLS session.
//
// The signature check, statement type check, and wire-token parsing are
// deployment-specific. This helper only enforces the source-of-authority
// relationship between the verified grant, the signer key, and the session
// binding fields.
type VerifiedSessionBindingStatement struct {
	GrantHash string
	Audience  string
	SignerKey string
	Binding   Binding
}

// NewAssertionFromSessionBinding builds an Assertion from a verified grant and
// a verified session-binding statement.
func NewAssertionFromSessionBinding(grant VerifiedGrant, statement VerifiedSessionBindingStatement, now time.Time) (Assertion, error) {
	if err := ValidateSessionBindingStatement(grant, statement, now); err != nil {
		return Assertion{}, err
	}
	return Assertion{
		Issuer:  grant.Issuer,
		Values:  grant.Values,
		Binding: statement.Binding,
	}, nil
}

// ValidateSessionBindingStatement checks that the statement is authorized by
// the grant and contains the minimum session-binding fields needed before
// ValidateAssertion compares it with the accepted aTLS session.
func ValidateSessionBindingStatement(grant VerifiedGrant, statement VerifiedSessionBindingStatement, now time.Time) error {
	var errs ValidationErrors

	if err := validateExpectedString(LayerIdentityGrant, FieldIssuer, grant.Issuer); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedString(LayerIdentityGrant, FieldAudience, grant.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedString(LayerIdentityGrant, FieldGrantHash, grant.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateObservedString(LayerSessionBinding, FieldGrantHash, statement.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.GrantHash != statement.GrantHash {
		errs = append(errs, validationError(LayerSessionBinding, FieldGrantHash, ErrMismatch))
	}
	if err := validateObservedString(LayerSessionBinding, FieldAudience, statement.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.Audience != statement.Audience {
		errs = append(errs, validationError(LayerSessionBinding, FieldAudience, ErrMismatch))
	}
	if err := validateObservedString(LayerSessionBinding, FieldSignerKey, statement.SignerKey); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if !grant.allowsBindingKey(statement.SignerKey) {
		errs = append(errs, validationError(LayerSessionBinding, FieldSignerKey, ErrUnauthorizedBindingKey))
	}
	if !grant.hasBindingKey() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldConfirmationKey, ErrMissingExpected))
	}
	if err := validateGrantLifetime(grant, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateStatementBinding(statement.Binding, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateGrantLifetime(grant VerifiedGrant, now time.Time) error {
	var errs ValidationErrors
	if grant.ExpiresAt.IsZero() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrMissingExpected))
	} else if !now.IsZero() && now.After(grant.ExpiresAt) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrExpiredAssertion))
	}
	if !grant.IssuedAt.IsZero() && !now.IsZero() && grant.IssuedAt.After(now) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldIssuedAt, ErrFutureAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateStatementBinding(binding Binding, now time.Time) error {
	var errs ValidationErrors
	for _, f := range []struct {
		name  string
		value string
	}{
		{FieldLeafPublicKeyHash, binding.LeafPublicKeySHA256},
		{FieldRequestContextHash, binding.RequestContextSHA256},
		{FieldNonce, binding.Nonce},
	} {
		if err := validateBindingString(f.name, f.value); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if binding.AttestationBinderSHA256 != "" {
		if err := validateBindingString(FieldAttestationBinderHash, binding.AttestationBinderSHA256); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if binding.ExpiresAt.IsZero() {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding))
	} else if !now.IsZero() && now.After(binding.ExpiresAt) {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion))
	}
	if !binding.IssuedAt.IsZero() && !now.IsZero() && binding.IssuedAt.After(now) {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuedAt, ErrFutureAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateExpectedString(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingExpected)
	}
	if err := validateValue(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateObservedString(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingObserved)
	}
	if err := validateValue(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateBindingString(field, value string) error {
	if isEmpty(value) {
		return validationError(LayerSessionBinding, field, ErrMissingBinding)
	}
	if err := validateValue(value); err != nil {
		return validationError(LayerSessionBinding, field, err)
	}
	return nil
}

func (g VerifiedGrant) hasBindingKey() bool {
	if !isEmpty(g.ConfirmationKey) || !isEmpty(g.Values.AgentPublicKey) {
		return true
	}
	for _, key := range g.AuthorizedEndpointKeys {
		if !isEmpty(key) {
			return true
		}
	}
	return false
}

func (g VerifiedGrant) allowsBindingKey(key string) bool {
	if isEmpty(key) {
		return false
	}
	if key == g.ConfirmationKey || key == g.Values.AgentPublicKey {
		return true
	}
	for _, allowed := range g.AuthorizedEndpointKeys {
		if key == allowed {
			return true
		}
	}
	return false
}
