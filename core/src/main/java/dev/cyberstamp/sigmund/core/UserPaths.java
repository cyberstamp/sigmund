package dev.cyberstamp.sigmund.core;

import java.nio.file.Path;

/**
 * Paths a user writes, read as a shell reads them at the start: a leading {@code ~} is the user's
 * home directory.
 * <p>
 * Neither YAML nor a shell, after {@code --option=}, expands {@code ~}, so {@code ~/.gnupg} would
 * otherwise name a directory called {@code ~} under the current one. Tool settings expand through
 * {@link ToolSetting#pathFrom}; the CLI expands its own path options with the same rule, which is
 * why this is public.
 */
public final class UserPaths {

    private UserPaths() {
    }

    /**
     * Expands a leading {@code ~/}, or a bare {@code ~}, to the user's home directory. Anything else
     * — including {@code ~user/…} and a {@code ~} later in the path — is read as written.
     *
     * @param path the path as written
     * @return the path
     */
    public static Path expand(String path) {
        String userHome = System.getProperty("user.home");
        if (userHome != null && (path.equals("~") || path.startsWith("~/"))) {
            return Path.of(userHome, path.substring(1).replaceFirst("^/", ""));
        }
        return Path.of(path);
    }
}
