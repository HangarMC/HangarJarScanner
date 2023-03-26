package io.papermc.hangar.scanner.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

// PluginDataService
public final class JarUtil {

    public static Jar openJar(final String fileName, final InputStream file) throws IOException {
        if (fileName.endsWith(".jar")) {
            return new Jar(fileName, new JarInputStream(file));
        } else {
            final ZipInputStream stream = new ZipInputStream(file);

            ZipEntry zipEntry;
            while ((zipEntry = stream.getNextEntry()) != null) {
                final String name = zipEntry.getName();
                if (!zipEntry.isDirectory() && name.split("/").length == 1 && name.endsWith(".jar")) {
                    // todo what about multiple jars in one zip?
                    return new Jar(zipEntry.getName(), new JarInputStream(stream));
                }
            }

            throw new RuntimeException("version.new.error.jarNotFound");
        }
    }

    public record Jar(String fileName, JarInputStream stream) implements AutoCloseable {
        @Override
        public void close() throws IOException {
            this.stream.close();
        }
    }
}
