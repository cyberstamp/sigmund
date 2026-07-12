File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text

// commons-lang3 key is on keys.openpgp.org and should be fully identified
assert log.contains("Signer: Gary David Gregory (Code signing key) <ggregory@apache.org>") : "Should identify commons-lang3 signer"
assert log.contains("org.apache.commons:commons-lang3:3.14.0") : "Should list commons-lang3"

// jspecify key is NOT on keys.openpgp.org (only on keyserver.ubuntu.com),
// so the default keyserver cannot fetch it
assert log.contains("Signer: UNKNOWN (key not in keyring)") : "Should report jspecify signer as UNKNOWN"
assert log.contains("org.jspecify:jspecify:1.0.0") : "Should list jspecify"

// The update should still have modified the trust config
assert log.contains("Trust configuration updated") : "Should log config update"

// The config should have the original signer plus an entry for jspecify
File trustConfig = new File(basedir, "trust-config.yaml")
assert trustConfig.exists()
String yaml = trustConfig.text
assert yaml.contains("gary-gregory") : "Should still have original signer"
assert yaml.contains("org.jspecify") : "Should have added jspecify trust entry"

// Should not have duplicate section headers
int signersCount = yaml.split("signers:").length - 1
assert signersCount == 1 : "Should have exactly one signers: section, found ${signersCount}"
int trustCount = yaml.split("trust:").length - 1
assert trustCount == 1 : "Should have exactly one trust: section, found ${trustCount}"

// Comments should be preserved
assert yaml.contains("# Trust configuration for update test") : "Header comment should be preserved"
assert yaml.contains("# Gary Gregory signs commons-lang3") : "Inline comment should be preserved"

println "SUCCESS: updated trust-config.yaml with missing signer, preserved comments, and reported UNKNOWN for jspecify"
