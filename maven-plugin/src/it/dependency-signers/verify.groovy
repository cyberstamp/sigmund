File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text
assert log.contains("Inspecting signatures") : "Should log signature inspection start"
assert log.contains("Dependency Signers:") : "Should log the signers report"
assert log.contains("Summary:") : "Should log the summary"
assert !log.contains("BUILD FAILURE") : "Build should succeed"
println "SUCCESS: dependency-signers goal executed"
