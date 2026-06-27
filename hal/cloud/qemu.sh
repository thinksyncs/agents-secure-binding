#!/usr/bin/env bash
set -euo pipefail
shopt -s extglob

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

trim() {
    local value="$1"
    value="${value##+([[:space:]])}"
    value="${value%%+([[:space:]])}"
    printf '%s' "$value"
}

load_env_file() {
    local env_file="$1"
    local line key value

    [[ -f "$env_file" ]] || die "$env_file is missing"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "$line")"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" == *=* ]] || die "invalid env line: $line"

        key="$(trim "${line%%=*}")"
        value="$(trim "${line#*=}")"
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid env key: $key"

        if [[ "$value" != \"* && "$value" != \'* ]]; then
            value="$(trim "${value%%#*}")"
        fi
        if [[ ( "$value" == \"*\" && "$value" == *\" ) || ( "$value" == \'*\' && "$value" == *\' ) ]]; then
            value="${value:1:${#value}-2}"
        fi

        printf -v "$key" '%s' "$value"
    done < "$env_file"
}

require_var() {
    local name="$1"
    [[ -n "${!name:-}" ]] || die "$name is required"
}

require_cmd() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd is not installed"
}

is_true() {
    [[ "${1:-false}" == "true" ]]
}

normalize_host_data() {
    local host_data="$1"
    [[ ${#host_data} -eq 64 && "$host_data" =~ ^[[:xdigit:]]{64}$ ]] ||
        die "SEV_SNP_HOST_DATA must be exactly 64 hexadecimal characters"
    printf '%s' "$host_data"
}

require_base_config() {
    local required=(
        BASE_IMAGE BASE_IMAGE_URL CUSTOM_IMAGE DISK_SIZE QEMU_BINARY VM_NAME
        SMP_COUNT SMP_MAXCPUS MEMORY_SIZE MEMORY_SLOTS MAX_MEMORY
        NET_DEV_ID NET_DEV_HOST_FWD_AGENT NET_DEV_GUEST_FWD_AGENT
        VIRTIO_NET_PCI_DISABLE_LEGACY VIRTIO_NET_PCI_IOMMU_PLATFORM
        VIRTIO_NET_PCI_ADDR MONITOR
    )
    local name

    for name in "${required[@]}"; do
        require_var "$name"
    done

    [[ "$QEMU_BINARY" != *[[:space:]]* ]] || die "QEMU_BINARY must be a command or path"
}

require_non_snp_config() {
    local required=(
        OVMF_CODE_IF OVMF_CODE_FORMAT OVMF_CODE_UNIT OVMF_CODE
        OVMF_CODE_READONLY OVMF_VARS_IF OVMF_VARS_FORMAT
        OVMF_VARS_UNIT OVMF_VARS
    )
    local name

    for name in "${required[@]}"; do
        require_var "$name"
    done
}

require_snp_config() {
    local required=(
        OVMF_CODE_FILE MEM_ID SEV_SNP_ID SEV_SNP_CBIT_POS
        SEV_SNP_REDUCED_PHYS_BITS
    )
    local name

    for name in "${required[@]}"; do
        require_var "$name"
    done
}

construct_qemu_args() {
    QEMU_ARGS=()

    QEMU_ARGS+=("-name" "$VM_NAME")

    if is_true "${ENABLE_KVM:-false}"; then
        QEMU_ARGS+=("-enable-kvm")
    fi

    if [[ -n "${MACHINE:-}" ]]; then
        QEMU_ARGS+=("-machine" "$MACHINE")
    fi

    if [[ -n "${CPU:-}" ]]; then
        QEMU_ARGS+=("-cpu" "$CPU")
    fi

    QEMU_ARGS+=("-boot" "d")
    QEMU_ARGS+=("-smp" "$SMP_COUNT,maxcpus=$SMP_MAXCPUS")
    QEMU_ARGS+=("-m" "$MEMORY_SIZE,slots=$MEMORY_SLOTS,maxmem=$MAX_MEMORY")

    if ! is_true "${ENABLE_SEV_SNP:-false}"; then
        require_non_snp_config
        QEMU_ARGS+=("-drive" "if=$OVMF_CODE_IF,format=$OVMF_CODE_FORMAT,unit=$OVMF_CODE_UNIT,file=$OVMF_CODE,readonly=$OVMF_CODE_READONLY")
        QEMU_ARGS+=("-drive" "if=$OVMF_VARS_IF,format=$OVMF_VARS_FORMAT,unit=$OVMF_VARS_UNIT,file=$OVMF_VARS")
    fi

    QEMU_ARGS+=("-netdev" "user,id=$NET_DEV_ID,hostfwd=tcp::$NET_DEV_HOST_FWD_AGENT-:$NET_DEV_GUEST_FWD_AGENT")
    QEMU_ARGS+=("-device" "virtio-net-pci,disable-legacy=$VIRTIO_NET_PCI_DISABLE_LEGACY,iommu_platform=$VIRTIO_NET_PCI_IOMMU_PLATFORM,netdev=$NET_DEV_ID,addr=$VIRTIO_NET_PCI_ADDR,romfile=${VIRTIO_NET_PCI_ROMFILE:-}")

    if is_true "${ENABLE_SEV_SNP:-false}"; then
        local host_data=""
        local kernel_hash=""
        local enable_kernel_hash="${ENABLE_KERNEL_HASH:-${KERNEL_HASH:-false}}"

        require_snp_config
        QEMU_ARGS+=("-machine" "confidential-guest-support=$SEV_SNP_ID,memory-backend=$MEM_ID")
        QEMU_ARGS+=("-bios" "$OVMF_CODE_FILE")

        if [[ -n "${SEV_SNP_HOST_DATA:-}" ]]; then
            host_data=",host-data=$(normalize_host_data "$SEV_SNP_HOST_DATA")"
        fi

        if is_true "$enable_kernel_hash"; then
            kernel_hash=",kernel-hashes=on"
        fi

        QEMU_ARGS+=("-object" "memory-backend-memfd,id=$MEM_ID,size=$MEMORY_SIZE,share=true,prealloc=false")
        QEMU_ARGS+=("-object" "sev-snp-guest,id=$SEV_SNP_ID,cbitpos=$SEV_SNP_CBIT_POS,reduced-phys-bits=$SEV_SNP_REDUCED_PHYS_BITS$kernel_hash$host_data")
    fi

    QEMU_ARGS+=("-drive" "file=$SEED_IMAGE,media=cdrom")
    QEMU_ARGS+=("-drive" "file=$CUSTOM_IMAGE,if=none,id=disk0,format=qcow2")
    QEMU_ARGS+=("-device" "virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true")
    QEMU_ARGS+=("-device" "scsi-hd,drive=disk0")

    if is_true "${NO_GRAPHIC:-false}"; then
        QEMU_ARGS+=("-nographic")
    fi

    QEMU_ARGS+=("-monitor" "$MONITOR")
    QEMU_ARGS+=("-vnc" ":9")
}

if [[ $EUID -ne 0 ]]; then
    die "this script must be run as root"
fi

load_env_file ".env"
require_base_config
require_cmd wget
require_cmd cloud-localds
require_cmd qemu-img
require_cmd "$QEMU_BINARY"

if [[ ! -f "$BASE_IMAGE" ]]; then
    echo "Downloading base Ubuntu image..."
    wget -q "$BASE_IMAGE_URL" -O "$BASE_IMAGE" --show-progress
fi

echo "Creating custom QEMU image..."
qemu-img create -f qcow2 -b "$BASE_IMAGE" -F qcow2 "$CUSTOM_IMAGE" "$DISK_SIZE"

CLOUD_CONFIG="config.yaml"
META_DATA="meta-data"
SEED_IMAGE="seed.img"

echo "Creating seed image..."
cloud-localds "$SEED_IMAGE" "$CLOUD_CONFIG" "$META_DATA"

construct_qemu_args

printf 'Running QEMU with the following arguments:'
printf ' %q' "${QEMU_ARGS[@]}"
printf '\n'
echo "Starting QEMU VM..."
exec "$QEMU_BINARY" "${QEMU_ARGS[@]}"
