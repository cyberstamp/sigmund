package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.Sigmund;
import dev.cyberstamp.sigmund.core.SigmundException;
import dev.cyberstamp.sigmund.core.SignedFile;
import dev.cyberstamp.sigmund.core.Signer;
import dev.cyberstamp.sigmund.core.SigningInfo;
import dev.cyberstamp.sigmund.core.SigningOutput;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;

/**
 * Signs all project artifacts using the tool chain configured in {@code sigmund.yaml}.
 * <p>
 * Bound to the VERIFY phase. Creates detached signature files for the main artifact,
 * POM, and all attached artifacts. The signature format and extension are determined
 * by the signing tools (e.g., {@code .asc} for OpenPGP, {@code .sigstore.json} for
 * Sigstore). Signing tools and their priority are determined by the
 * {@code signing.tools} section of {@code sigmund.yaml}; Mojo parameters act as
 * overrides.
 *
 * @see Sigmund
 * @see Signer
 */
@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SignMojo extends AbstractSigningMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Inject
    private MavenProjectHelper projectHelper;

    @Override
    public void execute() throws MojoExecutionException {
        if (skip) {
            getLog().info("Skipping signing");
            return;
        }
        try (Sigmund sigmund = buildSigningSigmund()) {
            Signer signer = sigmund.signer();
            for (SigningInfo info : signer.plan().keys()) {
                getLog().info(info.display());
            }
            List<FileToSign> filesToSign = collectFilesToSign(sigmund.signatureFileExtensions());

            getLog().info("Signing " + filesToSign.size() + " artifact(s)...");

            for (FileToSign fileToSign : filesToSign) {
                signAndAttach(fileToSign, signer);
            }

            getLog().info("Signing completed successfully");
        } catch (Exception e) {
            if (e instanceof MojoExecutionException mee) {
                throw mee;
            }
            throw new MojoExecutionException("Signing failed", e);
        }
    }

    private List<FileToSign> collectFilesToSign(Set<String> sigExtensions) {
        List<FileToSign> files = new ArrayList<>();

        Artifact mainArtifact = project.getArtifact();
        File mainFile = mainArtifact.getFile();
        if (mainFile != null && mainFile.exists() && !isSignatureFile(mainFile.getName(), sigExtensions)) {
            String extension = mainArtifact.getArtifactHandler().getExtension();
            files.add(new FileToSign(mainFile, extension, null));
            getLog().debug("Added main artifact: " + mainFile.getName());
        }

        File pomFile = project.getFile();
        if (pomFile != null && pomFile.exists()) {
            files.add(new FileToSign(pomFile, "pom", null));
            getLog().debug("Added POM: " + pomFile.getName());
        }

        for (Artifact artifact : project.getAttachedArtifacts()) {
            File file = artifact.getFile();
            if (file != null && file.exists() && !isSignatureFile(file.getName(), sigExtensions)) {
                String extension = artifact.getArtifactHandler().getExtension();
                String classifier = getClassifier(artifact);
                files.add(new FileToSign(file, extension, classifier));
                getLog().debug("Added attached artifact: " + file.getName() +
                        " (classifier=" + classifier + ")");
            }
        }

        return files;
    }

    private void signAndAttach(FileToSign fileToSign, Signer signer)
            throws MojoExecutionException {
        File file = fileToSign.file;
        Path artifactPath = file.toPath();

        getLog().info("Signing: " + file.getName());

        try {
            SigningOutput output = signer.sign(artifactPath, Path.of(project.getBuild().getDirectory()));
            for (SignedFile sf : output.files()) {
                String attachExtension = fileToSign.extension + sf.fileExtension();
                projectHelper.attachArtifact(project, attachExtension, fileToSign.classifier, sf.path().toFile());
                getLog().debug("Attached signature: " + sf.path().getFileName()
                        + (fileToSign.classifier != null
                                ? " (classifier=" + fileToSign.classifier + ")"
                                : ""));
            }
        } catch (SigmundException e) {
            throw new MojoExecutionException("Failed to sign " + file.getName(), e);
        }
    }

    private String getClassifier(Artifact artifact) {
        String classifier = artifact.getClassifier();
        return (classifier != null && !classifier.isEmpty()) ? classifier : null;
    }

    /**
     * Checks whether the given file name has a known signature extension.
     *
     * @param fileName the file name to check
     * @param sigExtensions the set of signature file extensions from registered formats
     * @return {@code true} if the name ends with a known signature extension
     */
    private static boolean isSignatureFile(String fileName, Set<String> sigExtensions) {
        for (String ext : sigExtensions) {
            if (fileName.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static class FileToSign {
        final File file;
        final String extension;
        final String classifier;

        FileToSign(File file, String extension, String classifier) {
            this.file = file;
            this.extension = extension;
            this.classifier = classifier;
        }
    }
}
