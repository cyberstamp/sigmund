package io.github.aloubyansky.pqc.maven.cli;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import picocli.CommandLine;

public class VersionProvider implements CommandLine.IVersionProvider {

    @Override
    public String[] getVersion() {
        Properties props = new Properties();
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("version.properties")) {
            if (is != null) {
                props.load(is);
            }
        } catch (IOException ignored) {
        }
        return new String[] { "pqc-sign " + props.getProperty("version", "unknown") };
    }
}
