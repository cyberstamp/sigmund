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

def props = new File(basedir, "test.properties")
props.text = "sigmund.fingerprint=${fingerprint}\nsigmund.sqHome=${sqHome.absolutePath}\n"
return true
