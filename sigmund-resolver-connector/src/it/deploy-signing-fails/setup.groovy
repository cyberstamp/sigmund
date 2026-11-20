evaluate(new File(fixtures, 'signing.groovy'))
// The modern profile asks for a v6 key, and the only key is v4
new File(basedir, '.mvn/maven.config') << '-Dsigmund.resolver.sign.profile=modern\n'
true
