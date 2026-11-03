File jarAsc = new File(basedir, "target/sign-with-profile-1.0-SNAPSHOT.jar.asc")
assert jarAsc.exists() : ".asc signature file was not created"

String content = jarAsc.text
assert content.count("-----BEGIN PGP SIGNATURE-----") == 1 :
        "The classic profile should sign with the v4 key alone:\n${content}"

// The packet's version byte follows its header: an old-format header is a tag octet and one
// length octet for a small signature, a new-format header a tag octet and its length octets.
def body = content.readLines()
        .dropWhile { !it.startsWith("-----BEGIN") }
        .drop(1)
        .dropWhile { it.trim() }
        .drop(1)
        .takeWhile { !it.startsWith("=") && !it.startsWith("-----END") }
        .join("")
byte[] packet = body.decodeBase64()
int tag = packet[0] & 0xFF
int offset
if ((tag & 0x40) != 0) {
    int first = packet[1] & 0xFF
    offset = first < 192 ? 2 : first < 224 ? 3 : 6
} else {
    offset = 1 + [1, 2, 4][tag & 0x03]
}
int version = packet[offset] & 0xFF
assert version == 4 : "Expected a v4 signature from the classic profile, got v${version}"

println "SUCCESS: the classic profile signed with the v4 key only"
