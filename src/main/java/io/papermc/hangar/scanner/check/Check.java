package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;

public interface Check {

    /**
     * Returns the last internal scanner version the check was updated in.
     *
     * @return last internal scanner version the check was updated in
     */
    int updatedAt();

    interface CheckResult {
        String location();

        String message();

        Severity severity();

        default String format() {
            return "[" + severity().name() + "]: " + message() + " at " + location();
        }
    }

    record SimpleCheckResult(Severity severity, String location, String message) implements CheckResult {

    }

    record ExceptionCheckResult(Severity severity, String location, String message, Exception exception) implements CheckResult {

    }
}
