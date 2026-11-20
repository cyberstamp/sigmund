import dev.cyberstamp.sigmund.core.Sigmund
import dev.cyberstamp.sigmund.core.SigmundConfig

// The jar and the POM are deployed with a signature that verifies against the deployed file
def log = new File(basedir, 'build.log').text
assert log.contains('Sigmund signs artifacts with') : 'the generator did not load sigmund.yaml'
assert log.contains('BUILD SUCCESS')

def deployed = new File(basedir, 'target/deploy-repo/org/example/sigmund/it/test/deploy-signed/1.0')
def config = SigmundConfig.parse(new File(basedir, 'sigmund.yaml').toPath())
Sigmund.builder().config(config).build().withCloseable { sigmund ->
    ['jar', 'pom'].each { extension ->
        def file = new File(deployed, "deploy-signed-1.0.${extension}")
        def signature = new File(deployed, "deploy-signed-1.0.${extension}.asc")
        assert signature.isFile() : "${signature.name} was not deployed"
        assert sigmund.verify(file.toPath(), signature.toPath()).isPass() : "${signature.name} does not verify"
    }
}
true
