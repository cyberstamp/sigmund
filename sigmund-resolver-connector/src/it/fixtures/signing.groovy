import dev.cyberstamp.sigmund.core.KeyGenerator
import dev.cyberstamp.sigmund.core.Sigmund

// Shared setup of the deploy ITs: loads the extension like the other ITs, then signs instead of verifying, with a
// v4 key generated here. Profiles: classic signs with it, modern asks for a v6 key there is none of.
evaluate(new File(fixtures, 'common.groovy'))
def path = { File f -> f.absolutePath.replace('\\', '/') }
def keys = new File(basedir, 'keys')
def gnupg = new File(keys, 'gnupg')
gnupg.mkdirs()
def tools = ['cert-d-home': path(new File(keys, 'cert-d')), 'bc-private-home': path(new File(keys, 'bc-private')),
             'gnupg-home': path(gnupg)]
def fingerprint = Sigmund.builder().addSigningTool('bc', tools).build().withCloseable {
    it.findTool(KeyGenerator).generateKey('Deploy IT <deploy@sigmund.example>', 'ed25519', 'pgp4')
}

new File(basedir, '.mvn/maven.config').text = '-Dsigmund.resolver.sign.enabled=true\n'
new File(basedir, 'sigmund.yaml').text = """\
signers:
  deployer:
    pgp4: "${fingerprint}"
rules:
  - match: ["org.example.sigmund.it.test:*"]
    requires: [deployer]
signing:
  toolchain: [bc]
  profiles:
    classic: [pgp4]
    modern: [pgp6]
verification:
  toolchain: [bc]
  resolve-signers: false
tools:
  bc:
    cert-d-home: "${tools['cert-d-home']}"
    bc-private-home: "${tools['bc-private-home']}"
    gnupg-home: "${tools['gnupg-home']}"
    signing-fingerprint: "${fingerprint}"
"""
