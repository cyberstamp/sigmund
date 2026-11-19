import java.util.regex.Pattern

// Verify sq is available
def sqCheck = new ProcessBuilder("sq", "version").start()
sqCheck.waitFor()
assert sqCheck.exitValue() == 0 : "sq is not available on PATH"

// Verify gpg is available
def gpgCheck = new ProcessBuilder("gpg", "--version").start()
gpgCheck.waitFor()
assert gpgCheck.exitValue() == 0 : "gpg is not available on PATH"

def sqHome = new File(basedir, "target/sq-home")
sqHome.mkdirs()

def pb = new ProcessBuilder(
        "sq", "key", "generate",
        "--userid", "IT Test <it@sigmund.test>",
        "--cipher-suite", "mldsa87-ed448",
        "--profile", "rfc9580",
        "--own-key",
        "--without-password")
pb.directory(basedir)
pb.environment().put("SEQUOIA_HOME", sqHome.absolutePath)
pb.redirectErrorStream(true)

def proc = pb.start()
def output = proc.inputStream.text
proc.waitFor()

assert proc.exitValue() == 0 : "sq key generate failed:\n${output}"

def matcher = Pattern.compile("(?i)(?:fingerprint:?\\s*)?([0-9A-F]{64})").matcher(output)
assert matcher.find() : "Could not find fingerprint in sq output:\n${output}"

def fingerprint = matcher.group(1)
println "Generated PQC key: ${fingerprint}"

// A GnuPG home of the test's own with a generated key, so the build never reads or signs with
// the user's keyring
def gpgHome = new File(basedir, "target/gnupg-home")
gpgHome.mkdirs()
gpgHome.setReadable(false, false); gpgHome.setReadable(true, true)
gpgHome.setWritable(false, false); gpgHome.setWritable(true, true)
gpgHome.setExecutable(false, false); gpgHome.setExecutable(true, true)
def gpgGen = new ProcessBuilder("gpg", "--batch", "--passphrase", "", "--pinentry-mode", "loopback",
        "--quick-gen-key", "--yes", "IT Test GnuPG <it-gpg@example.org>", "ed25519", "sign", "0")
gpgGen.environment().put("GNUPGHOME", gpgHome.absolutePath)
gpgGen.redirectErrorStream(true)
def gpgProc = gpgGen.start()
def gpgOutput = gpgProc.inputStream.text
gpgProc.waitFor()
assert gpgProc.exitValue() == 0 : "gpg --quick-gen-key failed:\n${gpgOutput}"

def sigmundYaml = new File(basedir, "sigmund.yaml")
sigmundYaml.text = """\
signing:
  toolchain: [gpg, sq]
tools:
  gpg:
    home: "${gpgHome.absolutePath}"
  sq:
    signing-fingerprint: "${fingerprint}"
"""

new File(basedir, "gpg-only.yaml").text = """\
verification:
  toolchain: [gpg]
  resolve-signers: false
tools:
  gpg:
    home: "${gpgHome.absolutePath}"
"""

def props = new File(basedir, "test.properties")
props.text = "sigmund.sqHome=${sqHome.absolutePath}\n"
return true
