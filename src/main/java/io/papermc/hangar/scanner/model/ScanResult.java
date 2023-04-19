package io.papermc.hangar.scanner.model;

import io.papermc.hangar.scanner.check.Check.CheckResult;
import java.util.List;

public record ScanResult(Severity highestSeverity, List<CheckResult> results) {
}
