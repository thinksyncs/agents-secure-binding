// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"
)

func TestValidateChallengeBindingRejectsStaleEvidence(t *testing.T) {
	challengeA := make([]byte, reportDataSize)
	challengeB := make([]byte, reportDataSize)
	challengeA[0] = 1
	challengeB[0] = 2

	if err := validateChallengeBinding(challengeA, challengeA); err != nil {
		t.Fatalf("validateChallengeBinding() rejected matching challenge: %v", err)
	}
	err := validateChallengeBinding(challengeA, challengeB)
	if !errors.Is(err, errChallengeMismatch) {
		t.Fatalf("validateChallengeBinding() error = %v, want errChallengeMismatch", err)
	}
}

func TestExtractSEVSNPEvidence(t *testing.T) {
	reportData := make([]byte, reportDataSize)
	reportData[0] = 0x7a
	hostData := make([]byte, 32)
	hostData[0] = 0x42
	encoded, err := proto.Marshal(&sevsnppb.Attestation{
		Report: &sevsnppb.Report{
			ReportData: reportData,
			HostData:   hostData,
		},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	extracted, err := extractSEVSNPEvidence(encoded)
	if err != nil {
		t.Fatalf("extractSEVSNPEvidence() error = %v", err)
	}
	if got := extracted.ReportData[0]; got != 0x7a {
		t.Fatalf("ReportData[0] = %#x, want 0x7a", got)
	}
	if got := extracted.HostData[0]; got != 0x42 {
		t.Fatalf("HostData[0] = %#x, want 0x42", got)
	}
}

func TestResolvePlatformRejectsUnsupportedInput(t *testing.T) {
	if _, err := resolvePlatform("azure"); err == nil {
		t.Fatal("resolvePlatform() accepted unsupported explicit platform")
	}
}

func TestWriteSummary(t *testing.T) {
	dir := t.TempDir()
	summary := &runSummary{
		TimestampUTC:     "2026-06-30T00:00:00Z",
		Platform:         platformSNP,
		EvidenceASHA256:  "evidence-a",
		EvidenceBSHA256:  "evidence-b",
		ChallengeASHA256: "challenge-a",
		ChallengeBSHA256: "challenge-b",
	}
	if err := writeSummary(dir, summary); err != nil {
		t.Fatalf("writeSummary() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); err != nil {
		t.Fatalf("summary.json was not written: %v", err)
	}
}
