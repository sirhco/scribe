// Lightweight string-anchor rules for high-signal secret prefixes that
// might appear in compiled binaries (debug strings, embedded configs,
// resource sections). Use these alongside `scribe secrets` for cross-check.

rule aws_access_key_anchor {
  strings:
    $akia = "AKIA"
    $asia = "ASIA"
  condition:
    any of them
}

rule github_pat_anchor {
  strings:
    $ghp = "ghp_"
    $gho = "gho_"
    $ghu = "ghu_"
    $ghs = "ghs_"
    $ghr = "ghr_"
  condition:
    any of them
}

rule slack_token_anchor {
  strings:
    $b = "xoxb-"
    $a = "xoxa-"
    $p = "xoxp-"
    $r = "xoxr-"
    $s = "xoxs-"
  condition:
    any of them
}

rule pem_block_anchor {
  strings:
    $rsa  = "-----BEGIN RSA PRIVATE KEY-----"
    $ec   = "-----BEGIN EC PRIVATE KEY-----"
    $pkcs = "-----BEGIN PRIVATE KEY-----"
    $ssh  = "-----BEGIN OPENSSH PRIVATE KEY-----"
  condition:
    any of them
}
