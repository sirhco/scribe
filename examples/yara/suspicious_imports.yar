// Heuristic YARA rules for scribe's subset engine. These match the symbol /
// import landscape characteristic of process injection, JIT loaders, and
// classic packer markers. They are deliberately broad — every match should
// be triaged manually.

rule windows_process_injection {
  meta:
    description = "Imports the canonical Windows remote-thread injection trio."
    severity    = "medium"
  strings:
    $vp  = "VirtualProtect"
    $vpe = "VirtualProtectEx"
    $wpm = "WriteProcessMemory"
    $crt = "CreateRemoteThread"
    $opp = "OpenProcess"
  condition:
    $opp and $wpm and ($crt or $vpe or $vp)
}

rule macho_process_injection {
  meta:
    description = "Mach-O imports task_for_pid + mach_vm_* (process injection)."
  strings:
    $tfp = "_task_for_pid"
    $vmw = "_mach_vm_write"
    $vmp = "_mach_vm_protect"
    $thr = "_thread_create_running"
  condition:
    $tfp and ($vmw or $vmp or $thr)
}

rule linux_ptrace_injector {
  meta:
    description = "ELF imports ptrace alongside dlopen — common ptrace injector pattern."
  strings:
    $pt    = "ptrace"
    $dlo   = "dlopen"
    $proc  = "/proc/"
  condition:
    $pt and $dlo and $proc
}

rule jit_marker_strings {
  meta:
    description = "Strings characteristic of JIT compilers and unsigned code execution."
  strings:
    $jit1 = "MAP_JIT"
    $jit2 = "PROT_EXEC"
    $jit3 = "mprotect"
    $jit4 = "mmap_jit"
    $jit5 = "allow-jit"
  condition:
    2 of them
}

rule upx_packer_signature {
  meta:
    description = "Classic UPX packer header signature."
  strings:
    $upx0 = "UPX0"
    $upx1 = "UPX1"
    $upx2 = "UPX!"
  condition:
    2 of them
}

rule embedded_shell_invocation {
  meta:
    description = "Strings indicating the binary spawns a shell with a command string."
  strings:
    $sh   = "/bin/sh"
    $bash = "/bin/bash"
    $cmd  = "cmd.exe"
    $sysc = "system"
    $execv = "execv"
  condition:
    ($sh or $bash or $cmd) and ($sysc or $execv)
}
