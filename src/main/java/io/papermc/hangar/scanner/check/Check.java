package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;

public interface Check {

    String name();

    /**
     * Returns the last internal scanner version the check was updated in.
     *
     * @return last internal scanner version the check was updated in
     */
    int updatedAt();

    interface CheckResult {
        String name();

        String location();

        String message();

        Severity severity();

        default String format() {
            return "[" + severity().name() + "]: [" + name() + "]: " + message() + " at " + location();
        }
    }

    record SimpleCheckResult(Severity severity, String name, String location, String message) implements CheckResult {

    }

    record ExceptionCheckResult(Severity severity, String name, String location, String message, Exception exception) implements CheckResult {

    }
}
