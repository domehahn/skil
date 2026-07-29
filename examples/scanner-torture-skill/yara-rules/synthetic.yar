rule synthetic_malware_fixture {
  meta:
    description = "Benign scanner fixture"
    category = "malware"
    severity = "CRITICAL"
    confidence = "0.99"
  strings:
    $m = "SAFE_SYNTHETIC_MALWARE_MARKER_2026"
  condition:
    $m
}

rule synthetic_webshell_fixture {
  meta:
    description = "Benign scanner fixture"
    category = "webshell"
    severity = "CRITICAL"
    confidence = "0.99"
  strings:
    $m = "SAFE_SYNTHETIC_WEBSHELL_MARKER_2026"
  condition:
    $m
}

rule synthetic_cryptominer_fixture {
  meta:
    description = "Benign scanner fixture"
    category = "cryptominer"
    severity = "HIGH"
    confidence = "0.99"
  strings:
    $m = "SAFE_SYNTHETIC_CRYPTOMINER_MARKER_2026"
  condition:
    $m
}

rule synthetic_hacktool_fixture {
  meta:
    description = "Benign scanner fixture"
    category = "hack_tool"
    severity = "HIGH"
    confidence = "0.99"
  strings:
    $m = "SAFE_SYNTHETIC_HACKTOOL_MARKER_2026"
  condition:
    $m
}
