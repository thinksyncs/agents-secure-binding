// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package clients contains the Direct-Agent client configuration and
// verifier-side observed-identity glue for Agents Secure Binding.
//
// This package is part of the repository's core Direct-Agent surface. It
// consumes accepted TLS or aTLS connection state and delegates final identity
// acceptance to pkg/atls/identitypolicy.
package clients
