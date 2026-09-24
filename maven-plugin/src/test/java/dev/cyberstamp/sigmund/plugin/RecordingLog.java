package dev.cyberstamp.sigmund.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.logging.Log;

/** Collects the report lines so the assertions can read what an operator would see. */
class RecordingLog implements Log {

    final List<String> lines = new ArrayList<>();

    private void record(String level, CharSequence content) {
        lines.add(level + ": " + content);
    }

    @Override
    public boolean isDebugEnabled() {
        return false;
    }

    @Override
    public void debug(CharSequence content) {
        record("debug", content);
    }

    @Override
    public void debug(CharSequence content, Throwable error) {
        record("debug", content);
    }

    @Override
    public void debug(Throwable error) {
        record("debug", String.valueOf(error));
    }

    @Override
    public boolean isInfoEnabled() {
        return true;
    }

    @Override
    public void info(CharSequence content) {
        record("info", content);
    }

    @Override
    public void info(CharSequence content, Throwable error) {
        record("info", content);
    }

    @Override
    public void info(Throwable error) {
        record("info", String.valueOf(error));
    }

    @Override
    public boolean isWarnEnabled() {
        return true;
    }

    @Override
    public void warn(CharSequence content) {
        record("warn", content);
    }

    @Override
    public void warn(CharSequence content, Throwable error) {
        record("warn", content);
    }

    @Override
    public void warn(Throwable error) {
        record("warn", String.valueOf(error));
    }

    @Override
    public boolean isErrorEnabled() {
        return true;
    }

    @Override
    public void error(CharSequence content) {
        record("error", content);
    }

    @Override
    public void error(CharSequence content, Throwable error) {
        record("error", content);
    }

    @Override
    public void error(Throwable error) {
        record("error", String.valueOf(error));
    }
}
