/*
  skil built-in malware indicators

  These rules intentionally require combinations of concrete behaviors. They
  are not derived from another scanner's rule pack and are kept small enough
  for review alongside the Go source.
*/

rule skil_reverse_shell_construction {
  meta:
    description = "Combines an interactive shell with a network transport"
    severity = "critical"
  strings:
    $shell = /\/bin\/(ba)?sh/
    $net_a = "socket.socket("
    $net_b = "nc -e "
    $dup = "dup2("
  condition:
    $shell and (any of ($net_*) or $dup)
}

rule skil_credential_collection_bundle {
  meta:
    description = "Collects multiple local credential stores"
    severity = "critical"
  strings:
    $ssh = ".ssh/id_rsa"
    $aws = ".aws/credentials"
    $kube = ".kube/config"
    $netrc = ".netrc"
  condition:
    2 of them
}

rule skil_agent_persistence_bundle {
  meta:
    description = "Installs executable content into a startup mechanism"
    severity = "high"
  strings:
    $cron = "crontab"
    $launch = "LaunchAgents"
    $systemd = "/etc/systemd/system"
    $write_a = "writeFile("
    $write_b = "open("
  condition:
    any of ($cron, $launch, $systemd) and any of ($write_*)
}

rule skil_encoded_executable_dropper {
  meta:
    description = "Decodes a large embedded payload before execution"
    severity = "critical"
  strings:
    $decode_a = "base64.b64decode("
    $decode_b = "Buffer.from("
    $exec_a = "subprocess."
    $exec_b = "child_process."
    $blob = /[A-Za-z0-9+\/]{512,}={0,2}/
  condition:
    any of ($decode_*) and any of ($exec_*) and $blob
}
