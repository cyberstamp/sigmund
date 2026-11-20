// Shared setup, evaluated by each IT's setup.groovy: loads the extension, enables verification and writes
// sigmund.yaml trusting the fixture key. Script variables: basedir, localRepositoryPath, projectVersion, fixtures.
def fixturesDir = new File(fixtures)
def path = { File f -> f.absolutePath.replace('\\', '/') }

def dotMvn = new File(basedir, '.mvn')
dotMvn.mkdirs()
new File(dotMvn, 'extensions.xml').text = """<extensions>
  <extension>
    <groupId>dev.cyberstamp.sigmund</groupId>
    <artifactId>sigmund-resolver-connector</artifactId>
    <version>${projectVersion}</version>
  </extension>
</extensions>
"""
new File(dotMvn, 'maven.config').text = '-Dsigmund.resolver.verify.enabled=true\n'

def gnupg = new File(basedir, 'gnupg')
gnupg.mkdirs()
new File(basedir, 'sigmund.yaml').text = new File(fixturesDir, 'sigmund.yaml').text
        .replace('@CERT_D@', path(new File(fixturesDir, 'cert-d')))
        .replace('@BC_PRIVATE@', path(new File(basedir, 'bc-private')))
        .replace('@GNUPG@', path(gnupg))

// Copies a fixture artifact, with its signatures, into the local repository as if cached by an earlier build
seedLocalRepository = { String artifactId ->
    def relative = "org/example/sigmund/it/${artifactId}/1.0"
    def target = new File(localRepositoryPath, relative)
    target.mkdirs()
    new File(fixturesDir, "cache/${relative}").eachFile { f -> new File(target, f.name).bytes = f.bytes }
}

// The local repository directory of a fixture artifact
localArtifactDir = { String artifactId -> new File(localRepositoryPath, "org/example/sigmund/it/${artifactId}/1.0") }
