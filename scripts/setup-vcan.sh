#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright (c) 2026 TPT Solutions
#
# Creates a virtual CAN interface (default vcan0) for the SocketCAN tests.
# Linux only; needs root. On some cloud kernels the vcan module is in the
# linux-modules-extra package.
set -eu
iface="${1:-vcan0}"
sudo modprobe vcan
sudo ip link add dev "$iface" type vcan 2>/dev/null || true
sudo ip link set up "$iface"
echo "$iface is up. Run: cargo test --features can-socketcan --test socketcan"
