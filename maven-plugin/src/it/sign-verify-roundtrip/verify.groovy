File buildDir = new File(basedir, "target")
assert buildDir.exists() : "target directory missing"

File jarAsc = new File(buildDir, "sign-verify-roundtrip-1.0-SNAPSHOT.jar.asc")
assert jarAsc.exists() : ".asc signature file was not created"

String content = jarAsc.text
int beginCount = content.count("-----BEGIN PGP SIGNATURE-----")
int endCount = content.count("-----END PGP SIGNATURE-----")

assert beginCount == 2 : "Expected 2 PGP signature blocks, found ${beginCount}"
assert endCount == 2 : "Expected 2 PGP end markers, found ${endCount}"

String log = new File(basedir, "build.log").text
assert log.contains("Overall: 2 VERIFIED") : "verify-signature with the project's sigmund.yaml did not verify both blocks"
assert log =~ /\[2\] INDETERMINATE \[UNSUPPORTED_ALGORITHM\] \(ML-DSA-87\+Ed448\)/ :
        "the gpg-only configuration did not leave the PQC block unchecked"
assert log.contains("Not all signatures could be verified (1 VERIFIED, 1 INDETERMINATE)") :
        "the gpg-only configuration did not fail strict verification"

println "SUCCESS: hybrid .asc file contains classic + PQC signature blocks, and verify-signature reads sigmund.yaml"
