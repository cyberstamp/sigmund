// A download without a signature is no claim, which the policy fails; the missing .asc is not a transfer error
evaluate(new File(fixtures, 'common.groovy'))
def log = new File(basedir, 'build.log').text

assert log.contains('org.example.sigmund.it:unsigned-lib:1.0 NO_CLAIM, action FAIL') : 'the unsigned jar was not judged as no claim'
assert !log.contains('Could not fetch signature') : 'a missing signature was treated as a transfer failure'
assert !new File(localArtifactDir('unsigned-lib'), 'unsigned-lib-1.0.jar').exists() : 'the blocked jar stayed in the local repository'
