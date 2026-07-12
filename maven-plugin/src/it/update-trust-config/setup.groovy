// Create a clean GPG home so the test doesn't depend on the user's keyring state.
// The jspecify key is not served with UID by keys.openpgp.org, so GPG will skip it.
def gpghome = new File(basedir, "gpghome")
gpghome.mkdirs()
gpghome.setReadable(false, false)
gpghome.setReadable(true, true)
gpghome.setWritable(false, false)
gpghome.setWritable(true, true)
gpghome.setExecutable(false, false)
gpghome.setExecutable(true, true)

// Create a partial trust-config.yaml that only covers commons-lang3.
// Includes a comment that should be preserved after update.
// The update goal should add the missing jspecify signer.
def config = new File(basedir, "trust-config.yaml")
config.text = """\
# Trust configuration for update test
signers:
  # Gary Gregory signs commons-lang3
  gary-gregory:
    pgp4: "2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB"
    uid: "Gary David Gregory (Code signing key) <ggregory@apache.org>"

trust:
  org.apache.commons:commons-lang3: gary-gregory
"""
println "Created partial trust-config.yaml (commons-lang3 only, with comments)"
println "Created clean GNUPGHOME at ${gpghome}"
return true
