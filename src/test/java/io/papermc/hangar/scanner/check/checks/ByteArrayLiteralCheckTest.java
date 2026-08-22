package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.CheckContext;
import java.io.IOException;
import java.io.InputStream;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.papermc.hangar.scanner.HangarJarScanner;
import org.junit.jupiter.api.Test;

class ByteArrayLiteralCheckTest {

    private final HangarJarScanner scanner = new HangarJarScanner();

    @Test
    void flagsByteArrayLiteral() throws IOException {
        var scanResult = scanner.scanClazz(new CheckContext(), readClassBytes(ByteArrayLiteralSample.class), ByteArrayLiteralSample.class.getName());

        assertTrue(scanResult.stream().anyMatch(result -> result.message().startsWith("creates byte array literal")));
    }

    @Test
    void doesNotFlagSizedByteArrayAllocation() throws IOException {
        var scanResult = scanner.scanClazz(new CheckContext(), readClassBytes(SizedByteArraySample.class), SizedByteArraySample.class.getName());

        assertFalse(scanResult.stream().anyMatch(result -> result.message().startsWith("creates byte array literal")));
    }

    private static byte[] readClassBytes(Class<?> type) throws IOException {
        String resourceName = "/" + type.getName().replace('.', '/') + ".class";
        try (InputStream stream = ByteArrayLiteralCheckTest.class.getResourceAsStream(resourceName)) {
            if (stream == null) {
                throw new IOException("Missing class resource: " + resourceName);
            }
            return stream.readAllBytes();
        }
    }

    static class ByteArrayLiteralSample {
        byte[] sample() {
            return new byte[] {1, 2, 3};
        }
    }

    static class SizedByteArraySample {
        byte[] sample() {
            return new byte[3];
        }
    }
}
