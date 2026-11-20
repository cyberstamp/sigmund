// A download whose signature does not match is FAILED, and neither it nor its signature is kept
evaluate(new File(fixtures, 'common.groovy'))
def log = new File(basedir, 'build.log').text
assert !log.contains('NOT allowed from') : 'remote repository filtering, not Sigmund, refused an artifact'
def dir = localArtifactDir('tampered-lib')

assert log.contains('org.example.sigmund.it:tampered-lib:1.0 FAILED, action FAIL') : 'the tampered jar was not blocked'
assert !new File(dir, 'tampered-lib-1.0.jar').exists() : 'the blocked jar stayed in the local repository'
assert !new File(dir, 'tampered-lib-1.0.jar.asc').exists() : 'the blocked jar\'s signature stayed in the local repository'
assert new File(dir, 'tampered-lib-1.0.pom').isFile() : 'the signed POM should have passed'
