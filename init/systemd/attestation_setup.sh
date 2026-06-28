#!/bin/bash
set -e

# Setup permissions for attestation socket directory
mkdir -p /run/agents-secure-binding
chmod 755 /run/agents-secure-binding
