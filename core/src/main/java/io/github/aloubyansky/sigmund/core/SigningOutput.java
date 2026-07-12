package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * The output of a signing operation, carrying metadata about each produced file.
 *
 * @param files the list of produced signature files with metadata
 */
public record SigningOutput(List<SignedFile> files) {

    /**
     * Creates a signing output with a defensive copy.
     */
    public SigningOutput {
        files = List.copyOf(files);
    }
}
