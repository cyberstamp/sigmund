// A signing failure fails the deploy, before anything is uploaded
def log = new File(basedir, 'build.log').text
assert log.contains('Sigmund signs with profile modern')
assert log.contains('no signing key for requested credential type pgp6') : 'the deploy did not fail on signing'
assert !new File(basedir, 'target/deploy-repo').exists() : 'something was deployed although signing failed'
true
