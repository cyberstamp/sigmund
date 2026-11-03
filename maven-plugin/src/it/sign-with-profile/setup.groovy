import java.util.regex.Pattern

def sqHome = new File(basedir, "target/sq-home")
sqHome.mkdirs()

/** Generates an sq key with the given profile and returns its fingerprint. */
def generate(File home, String userId, String profile) {
    def pb = new ProcessBuilder("sq", "key", "generate", "--userid", userId,
            "--cipher-suite", "cv25519", "--profile", profile, "--own-key", "--without-password")
    pb.directory(basedir)
    pb.environment().put("SEQUOIA_HOME", home.absolutePath)
    pb.redirectErrorStream(true)
    def proc = pb.start()
    def output = proc.inputStream.text
    proc.waitFor()
    assert proc.exitValue() == 0 : "sq key generate failed:\n${output}"
    def matcher = Pattern.compile("(?i)(?:fingerprint:?\\s*)?([0-9A-F]{64}|[0-9A-F]{40})").matcher(output)
    assert matcher.find() : "Could not find fingerprint in sq output:\n${output}"
    return matcher.group(1)
}

def v4 = generate(sqHome, "IT Classic <classic@sigmund.test>", "rfc4880")
def v6 = generate(sqHome, "IT Modern <modern@sigmund.test>", "rfc9580")

new File(basedir, "sigmund.yaml").text = """\
signing:
  toolchain: [sq]
  profiles:
    classic: [pgp4]
tools:
  sq:
    signing-fingerprint: [${v4}, ${v6}]
"""

new File(basedir, "test.properties").text = "sigmund.sqHome=${sqHome.absolutePath}\nsigmund.profile=classic\n"
return true
