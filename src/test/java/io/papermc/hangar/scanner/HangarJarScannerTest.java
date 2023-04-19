package io.papermc.hangar.scanner;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.model.ScanResult;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class HangarJarScannerTest {

    private HangarJarScanner scanner;

    @BeforeEach
    void setup() {
        this.scanner = new HangarJarScanner();
    }

    @Test
    void test() throws IOException {
        Path path = Path.of("stuff/malware");
        Files.list(path).forEach(f -> {
            try {
                System.out.println("#-- " + f.getFileName() + " --#");
                ScanResult scanResult = scanner.scanJar(Files.newInputStream(f), f.getFileName().toString());
                if (!scanResult.results().isEmpty()) {
                    String checks = scanResult.results().stream().map(Check.CheckResult::format).collect(Collectors.joining("\n"));
                    System.out.println(checks);
                } else {
                    System.out.println("no matches for " + f.getFileName());
                }

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void testSingle() throws IOException {
        String fileName = "";
        ScanResult scanResult = scanner.scanJar(Files.newInputStream(Path.of("stuff/malware").resolve(fileName)), fileName);
        System.out.println();
        if (!scanResult.results().isEmpty()) {
            String checks = scanResult.results().stream().map(Check.CheckResult::format).collect(Collectors.joining("\n"));
            System.out.println(checks);
        }
    }
}
