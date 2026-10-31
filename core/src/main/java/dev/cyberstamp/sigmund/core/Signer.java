package dev.cyberstamp.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Producer use case — signing artifacts.
 * <p>
 * Signs an artifact with the keys its {@link SigningPlan} selects, groups results by
 * {@link SignatureFormat}, and combines compatible formats into single files.
 * <p>
 * The plan is worked out when the signer is created, so each tool is asked for its keys once
 * however many artifacts are signed. A signer may be used to sign from several threads.
 *
 * <h2>Sign flow</h2>
 * <ol>
 * <li>Refuse to sign when the plan has a problem, before any tool signs</li>
 * <li>Call {@code sign()} on each tool once per planned key → {@link SignResult} with
 * algorithm metadata</li>
 * <li>When {@code signing.signer} asserts a signer, check that every signature proves it</li>
 * <li>Group results by {@link SignatureFormat}</li>
 * <li>For combinable formats → merge into one output file</li>
 * <li>For non-combinable → write each as a separate file</li>
 * <li>Return {@link SigningOutput} with metadata per file</li>
 * </ol>
 *
 * @see SigningOutput
 */
public class Signer {

    private final Map<String, SignatureTool> toolsByName;
    private final SigningPlan plan;
    private final SignerBindingCheck check;

    /**
     * Creates a new signer with the given tools, asking each for its keys to work out the plan.
     *
     * @param tools the signing tools in signing order (must all have {@code canSign() → true}),
     *        with distinct names
     * @param requestedTypes the credential types the run requests, empty when none are
     * @param check the check every fresh signature must pass before anything is written, or
     *        {@code null} when {@code signing.signer} asserts no signer
     * @throws SigmundException if there is no tool, two tools share a name, or a tool reports a
     *         key carrying another tool's name
     */
    Signer(List<SignatureTool> tools, List<String> requestedTypes, SignerBindingCheck check) {
        if (tools.isEmpty()) {
            throw new SigmundException("No signing tools available");
        }
        this.toolsByName = byName(tools);
        this.plan = SigningPlan.of(tools, List.copyOf(requestedTypes));
        this.check = check;
    }

    private static Map<String, SignatureTool> byName(List<SignatureTool> tools) {
        Map<String, SignatureTool> result = new LinkedHashMap<>();
        for (SignatureTool tool : tools) {
            if (result.putIfAbsent(tool.name(), tool) != null) {
                throw new SigmundException("Two signing tools are named '" + tool.name() + "'");
            }
        }
        return result;
    }

    /**
     * Returns the signing plan: which tool signs with which key, and any problem that stops the
     * run from signing. Every {@link #sign(Path, Path)} call follows it.
     *
     * @return the signing plan
     */
    public SigningPlan plan() {
        return plan;
    }

    /**
     * Signs an artifact file and writes signature files to the output directory.
     * <p>
     * When the {@linkplain #plan() plan} has a problem, nothing is signed or written.
     * <p>
     * When {@code signing.signer} asserts a signer, every fresh signature must prove it before
     * anything is combined or written: if one does not, no signature file is written, a
     * signature file already in the output directory is left as it was, and the temporary
     * signatures are deleted.
     *
     * @param artifactFile the file to sign
     * @param outputDir the directory to write signature files to
     * @return the signing output with metadata per produced file
     * @throws ToolExecutionException if signing fails
     * @throws SigmundException if the plan has a problem, or a signature does not prove the
     *         asserted signer
     */
    public SigningOutput sign(Path artifactFile, Path outputDir) {
        plan.requireSignable();
        List<ToolSignResult> toolResults = signWithPlannedKeys(artifactFile, outputDir);
        try {
            checkSigner(artifactFile, toolResults);
            Map<String, List<ToolSignResult>> grouped = groupByFormatName(toolResults);
            return combineAndWrite(artifactFile, outputDir, grouped);
        } catch (RuntimeException e) {
            cleanupTempFiles(toolResults.stream().map(r -> r.tempFile).toList());
            throw e;
        }
    }

    /**
     * Signs the artifact once with each planned key, writing one temporary signature file per
     * key, in plan order.
     *
     * @param artifactFile the file to sign
     * @param outputDir the directory for temporary signature files
     * @return one result per planned key
     */
    private List<ToolSignResult> signWithPlannedKeys(Path artifactFile, Path outputDir) {
        List<ToolSignResult> results = new ArrayList<>(plan.keys().size());
        try {
            for (SigningInfo key : plan.keys()) {
                SignatureTool tool = toolsByName.get(key.toolName());
                Path tempSig = createTempSigFile(outputDir, tool);
                results.add(new ToolSignResult(tool, tempSig, null));
                SignResult result = tool.sign(artifactFile, tempSig, key);
                results.set(results.size() - 1, new ToolSignResult(tool, tempSig, result));
            }
        } catch (RuntimeException e) {
            cleanupTempFiles(results.stream().map(r -> r.tempFile).toList());
            throw e;
        }
        return results;
    }

    /**
     * Checks that each fresh signature proves the asserted signer, when one is asserted.
     *
     * @param artifactFile the signed artifact
     * @param results the per-key signing results
     * @throws SigmundException if a signature does not prove the signer
     */
    private void checkSigner(Path artifactFile, List<ToolSignResult> results) {
        if (check == null) {
            return;
        }
        for (ToolSignResult r : results) {
            check.check(artifactFile, r.tool, r.tempFile);
        }
    }

    /**
     * Groups tool results by their {@link SignatureFormat#name()}, preserving insertion order.
     *
     * @param results the per-tool signing results
     * @return results grouped by format name
     */
    private Map<String, List<ToolSignResult>> groupByFormatName(List<ToolSignResult> results) {
        Map<String, List<ToolSignResult>> grouped = new LinkedHashMap<>();
        for (ToolSignResult r : results) {
            grouped.computeIfAbsent(r.tool.signatureFormat().name(), k -> new ArrayList<>(2)).add(r);
        }
        return grouped;
    }

    /**
     * Combines compatible results into single files per format and writes the final output.
     * <p>
     * Formats that {@linkplain SignatureFormat#supportsCombining() support combining}
     * merge multiple tool outputs into one file (e.g., a v4+v6 armored OpenPGP file).
     * Non-combinable results are written as separate files.
     *
     * @param artifactFile the signed artifact (used for naming)
     * @param outputDir the output directory
     * @param grouped tool results grouped by format name
     * @return the signing output with metadata per produced file
     */
    private SigningOutput combineAndWrite(Path artifactFile, Path outputDir,
            Map<String, List<ToolSignResult>> grouped) {
        List<SignedFile> signedFiles = new ArrayList<>();
        String artifactName = artifactFile.getFileName().toString();

        for (var entry : grouped.entrySet()) {
            List<ToolSignResult> results = entry.getValue();
            SignatureFormat format = results.get(0).tool.signatureFormat();

            if (format.supportsCombining() && results.size() > 1) {
                signedFiles.add(combineResults(artifactName, outputDir, format, results));
            } else {
                for (ToolSignResult r : results) {
                    Path finalPath = outputDir.resolve(artifactName + format.fileExtension());
                    moveFile(r.tempFile, finalPath);
                    signedFiles.add(new SignedFile(finalPath, r.tool.name(),
                            format.name(), r.result.algorithm(), format.fileExtension()));
                }
            }
        }
        return new SigningOutput(signedFiles);
    }

    /**
     * Merges multiple tool results for the same format into a single signature file.
     *
     * @param artifactName the artifact file name (for deriving the output file name)
     * @param outputDir the output directory
     * @param format the signature format handling the merge
     * @param results the tool results to combine
     * @return the combined signed file with concatenated tool/algorithm names
     */
    private SignedFile combineResults(String artifactName, Path outputDir,
            SignatureFormat format, List<ToolSignResult> results) {
        Path combinedPath = outputDir.resolve(artifactName + format.fileExtension());
        List<Path> tempFiles = results.stream().map(r -> r.tempFile).toList();
        format.combine(tempFiles, combinedPath);
        cleanupTempFiles(tempFiles);
        String algorithms = results.stream()
                .map(r -> r.result.algorithm())
                .reduce((a, b) -> a + "+" + b)
                .orElse("unknown");
        String toolNames = results.stream()
                .map(r -> r.tool.name())
                .reduce((a, b) -> a + "+" + b)
                .orElse("unknown");
        return new SignedFile(combinedPath, toolNames, format.name(), algorithms, format.fileExtension());
    }

    /**
     * Creates a temporary file for a tool's signature output.
     *
     * @param outputDir the directory to create the file in
     * @param tool the tool (used to name the temp file)
     * @return the path to the new temp file
     * @throws ToolExecutionException if the file cannot be created
     */
    private Path createTempSigFile(Path outputDir, SignatureTool tool) {
        try {
            Files.createDirectories(outputDir);
            return Files.createTempFile(outputDir, "sig-" + tool.name() + "-", ".tmp");
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for signing", e);
        }
    }

    /**
     * Moves a file, replacing any existing target.
     *
     * @param source the file to move
     * @param target the destination path
     * @throws ToolExecutionException if the move fails
     */
    private void moveFile(Path source, Path target) {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to move signature file", e);
        }
    }

    /**
     * Deletes temporary files, ignoring any I/O errors.
     *
     * @param files the files to delete
     */
    private void cleanupTempFiles(List<Path> files) {
        for (Path f : files) {
            try {
                Files.deleteIfExists(f);
            } catch (IOException ignored) {
            }
        }
    }

    private record ToolSignResult(SignatureTool tool, Path tempFile, SignResult result) {
    }
}
