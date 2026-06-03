File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text
assert log.contains("Verifying") : "Should log verification start"
assert log.contains("unmapped") : "Should log unmapped dependencies"
assert log.contains("Summary:") : "Should log verification summary"
assert !log.contains("BUILD FAILURE") : "Build should succeed with unmappedPolicy=skip"
println "SUCCESS: verify-dependencies goal executed with unmapped dependencies"
