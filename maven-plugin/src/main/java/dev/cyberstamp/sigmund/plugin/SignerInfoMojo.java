package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigningPlan;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;

/**
 * Displays signing tool and identity information without performing any signing.
 */
@Mojo(name = "signer-info", requiresProject = false, threadSafe = true)
public class SignerInfoMojo extends AbstractSigningMojo {

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Skipping signer-info");
            return;
        }
        try (var sigmund = buildSigningSigmund()) {
            SigningPlan plan = signer(sigmund).plan();
            for (SigningInfo info : plan.keys()) {
                getLog().info(info.display());
            }
            if (!plan.problems().isEmpty()) {
                throw new MojoFailureException(String.join("; ", plan.problems()));
            }
        } catch (Exception e) {
            if (e instanceof MojoExecutionException || e instanceof MojoFailureException) {
                throw e;
            }
            throw new MojoExecutionException("Failed to retrieve signer info", e);
        }
    }
}
