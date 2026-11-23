File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text

File trustConfig = new File(basedir, "sigmund.yaml")
assert trustConfig.exists() : "sigmund.yaml should have been generated"
String yaml = trustConfig.text
assert yaml.contains("rules:") : "Generated config should have a rules section"
assert !yaml.contains("# signature could not be checked here") : "The signer's key should have been found"

assert log =~ /(?m)\bSATISFIED \(1\)/ && !(log =~ /(?m)UNSATISFIED/) : "The dependency should be SATISFIED"
assert !log.contains("could not be checked here") : "No signature should be left unchecked"
assert !log.contains("BUILD FAILURE") : "Build should succeed"

println "SUCCESS: a generated policy verified error_prone with the default keyservers"
