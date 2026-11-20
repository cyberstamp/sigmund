# Integration test fixtures

Shared by the ITs in `src/it`, which run the extension in real Maven builds.

- `cert-d/`: the public certificate of the test key `00C05E507E3CF2B57AB0A7F200480FF856DD9555`
  (`Sigmund IT <it@sigmund.example>`, Ed25519, v4), generated with Sigmund's Bouncy Castle
  backend. Its private key was not kept: the ITs only verify.
- `repo/`: a remote repository the IT projects declare, under `org.example.sigmund.it`, version
  `1.0`, each with a signed POM:
  - `signed-lib`: the jar signed.
  - `tampered-lib`: the jar rewritten after signing, so its `.asc` does not match.
  - `unsigned-lib`: the jar without a signature.
- `cache/`: artifacts seeded straight into the IT local repository, as if an earlier build had
  cached them, to exercise the post-processor: `cached-lib` (signed) and `cached-tampered-lib`
  (jar rewritten after signing).
- `sigmund.yaml`: requires the test key for `org.example.sigmund.it:*` and warns about
  everything else; `common.groovy` fills in its paths.
