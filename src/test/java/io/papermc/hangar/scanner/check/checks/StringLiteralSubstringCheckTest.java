package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.CheckContext;
import java.io.IOException;
import java.io.InputStream;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.papermc.hangar.scanner.HangarJarScanner;
import org.junit.jupiter.api.Test;

class StringLiteralSubstringCheckTest {

    private final HangarJarScanner scanner = new HangarJarScanner();

    @Test
    void flagsStringLiteralSubstring() throws IOException {
        var scanResult = scanner.scanClazz(new CheckContext(), readClassBytes(StringLiteralSubstringSample.class), StringLiteralSubstringSample.class.getName());

        assertTrue(scanResult.stream().anyMatch(result -> result.message().startsWith("contains banned string literal substring 'notme'")));
    }

    @Test
    void doesNotFlagOtherStringLiterals() throws IOException {
        var scanResult = scanner.scanClazz(new CheckContext(), readClassBytes(OtherStringLiteralSample.class), OtherStringLiteralSample.class.getName());

        assertFalse(scanResult.stream().anyMatch(result -> result.message().startsWith("contains banned string literal substring 'notme'")));
    }

    @Test
    void flagsStringLiteralFieldInitializer() throws IOException {
        var scanResult = scanner.scanClazz(new CheckContext(), readClassBytes(StringLiteralFieldSample.class), StringLiteralFieldSample.class.getName());

        assertTrue(scanResult.stream().anyMatch(result -> result.message().startsWith("contains banned string literal substring 'notme'")));
    }

    private static byte[] readClassBytes(Class<?> type) throws IOException {
        String resourceName = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream stream = StringLiteralSubstringCheckTest.class.getResourceAsStream(resourceName)) {
            if (stream == null) {
                throw new IOException("Missing class resource: " + resourceName);
            }
            return stream.readAllBytes();
        }
    }

    static class StringLiteralSubstringSample {
        String sample() {
            return "value with notme inside";
        }
    }

    static class OtherStringLiteralSample {
        String sample() {
            return "value without it";
        }
    }

    static class StringLiteralFieldSample {
        private static final String SAMPLE = "field value with notme inside";
    }
}
