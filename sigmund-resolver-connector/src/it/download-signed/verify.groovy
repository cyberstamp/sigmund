// A signed download passes, and its signatures stay next to it, registered in the local repository
evaluate(new File(fixtures, 'common.groovy'))
def log = new File(basedir, 'build.log').text
def dir = localArtifactDir('signed-lib')

assert log.contains('Sigmund verifies artifacts with') : 'the extension did not load sigmund.yaml'
assert log.contains('BUILD SUCCESS')
['signed-lib-1.0.jar', 'signed-lib-1.0.jar.asc', 'signed-lib-1.0.pom.asc'].each {
    assert new File(dir, it).isFile() : "${it} is not in the local repository"
}
assert new File(dir, '_remote.repositories').text.contains('signed-lib-1.0.jar.asc>sigmund-it') :
        'the signature was not registered with the local repository'
