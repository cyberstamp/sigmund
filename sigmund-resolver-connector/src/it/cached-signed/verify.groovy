// An artifact served from the local repository is checked against the signature stored next to it, and passes;
// the remote repository does not hold it, so it cannot have been downloaded
assert new File(basedir, 'build.log').text.contains('BUILD SUCCESS')
