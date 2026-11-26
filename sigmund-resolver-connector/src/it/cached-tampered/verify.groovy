// An artifact altered in the local repository is FAILED by the post-processor, and left where it is
evaluate(new File(fixtures, 'common.groovy'))
def log = new File(basedir, 'build.log').text
assert !log.contains('NOT allowed from') : 'remote repository filtering, not Sigmund, refused an artifact'

assert log.contains('org.example.sigmund.it:cached-tampered-lib:1.0 FAILED, action FAIL') : 'the tampered cached jar was not blocked'
assert new File(localArtifactDir('cached-tampered-lib'), 'cached-tampered-lib-1.0.jar').isFile() :
        'the post-processor should not delete a cached artifact'
