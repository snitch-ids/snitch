#!/bin/sh
# dracut pre-pivot hook: the root file system is mounted at $NEWROOT.
# If loading fails, the system still boots, and snitch --watch loads the
# monitoring programs itself, without self-protection.
if out=$(snitch-ebpf-load --root "$NEWROOT" 2>&1); then
    echo "snitch: $out" > /dev/kmsg
else
    echo "snitch: loading BPF programs failed: $out" > /dev/kmsg
fi
