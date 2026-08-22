package io.papermc.hangar.scanner.model;

import io.papermc.hangar.scanner.check.CheckResult;

import java.util.Set;

public record ScanResult(Severity highestSeverity, Set<CheckResult> results) {
}
