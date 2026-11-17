#!/bin/bash
# dracut module: load snitch's BPF programs (and their self-protection)
# after the root file system is mounted, before switch-root. Install to
# /usr/lib/dracut/modules.d/95snitch/, then dracut -f.

check() {
    require_binaries snitch-ebpf-load || return 1
    return 0
}

depends() {
    return 0
}

install() {
    inst_multiple snitch-ebpf-load
    inst_hook pre-pivot 90 "$moddir/snitch-load.sh"
}
