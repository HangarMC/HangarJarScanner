package io.papermc.hangar.scanner;

import io.papermc.hangar.scanner.check.Check.CheckResult;
import io.papermc.hangar.scanner.check.Check.ExceptionCheckResult;
import io.papermc.hangar.scanner.check.Check.SimpleCheckResult;
import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.check.MethodCheck.MethodCheckResult;
import io.papermc.hangar.scanner.check.method.*;
import io.papermc.hangar.scanner.model.Platform;
import io.papermc.hangar.scanner.model.ScanResult;
import io.papermc.hangar.scanner.model.Severity;
import io.papermc.hangar.scanner.util.JarUtil;
import io.papermc.hangar.scanner.util.JarUtil.Jar;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;

public class HangarJarScanner {

    private final List<MethodCheck> methodChecks = List.of(
            new ClassLoaderMethodCheck(),
            new OpenConnectionMethodCheck(),
            new SetOpMethodCheck(),
            new ThreadSleepMethodCheck(),
            new PluginLoaderCheck(),
            new SocketMethodCheck(),
            new StringEncryptionCheck(),
            new DispatchCommandCheck(),
            new ExecMethodCheck(),
            new TrollMethodCheck()
    );

    public List<ScanResult> scanJar(InputStream stream, String name) throws IOException {
        List<ScanResult> result = new ArrayList<>();
        try (final Jar jar = JarUtil.openJar(name, stream)) {
            JarEntry jarEntry;
            while ((jarEntry = jar.stream().getNextJarEntry()) != null) {
                byte[] bytes = jar.stream().readAllBytes();
                if (bytes.length < 4) {
                    continue;
                }
                String magic = String.format("%02X%02X%02X%02X", bytes[0], bytes[1], bytes[2], bytes[3]);
                if (magic.equals("CAFEBABE")) { // class file magic
                    if (jarEntry.getName().endsWith(".jnilib")) {
                        continue; // meh
                    }
                    ScanResult scanResult = scanClazz(bytes, jarEntry.getName());
                    if (scanResult != null) {
                        result.add(scanResult);
                    }
                    if (!jarEntry.getName().endsWith(".class")) {
                        result.add(new ScanResult(null, List.of(new SimpleCheckResult(Severity.HIGHEST, jarEntry.getName(), "disguised class file, starts with 0xCAFEBABE"))));
                    }
                } else if (jarEntry.getName().endsWith(".class")) {
                    result.add(new ScanResult(null, List.of(new SimpleCheckResult(Severity.HIGHEST, jarEntry.getName(), ".class file without 0xCAFEBABE"))));
                } else if (magic.startsWith("7F454C")) { // ELF magic
                    result.add(new ScanResult(null, List.of(new SimpleCheckResult(Severity.HIGHEST, jarEntry.getName(), "disguised linux executable binary file, starts with 0x7F454C (ELF)"))));
                }
            }
        } catch (Exception ex) {
            result.add(new ScanResult(null, List.of(new ExceptionCheckResult(Severity.HIGHEST, name, "Crashes while scanning with " + ex.getClass().getName() + ": " + ex.getMessage(), ex))));
        }
        return result;
    }

    public ScanResult scanClazz(byte[] bytes, String name) {
        ClassReader cr = new ClassReader(bytes);
        ClassNode cn = new ClassNode();
        try {
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return scan(cn);
    }

    private ScanResult scan(ClassNode classNode) {
        Platform platform = checkClassForPlatform(classNode);
        List<CheckResult> checkResults = new ArrayList<>();
        for (MethodNode method : classNode.methods) {
            checkResults.addAll(scan(method, classNode));
        }

        if (platform != null || !checkResults.isEmpty()) {
            return new ScanResult(platform, checkResults);
        } else {
            return null;
        }
    }

    private List<CheckResult> scan(MethodNode methodNode, ClassNode classNode) {
        List<CheckResult> checkResults = new ArrayList<>();
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction instanceof MethodInsnNode methodInsnNode) {
                for (MethodCheck methodCheck : methodChecks) {
                    MethodCheckResult result = methodCheck.check(methodInsnNode, methodNode, classNode);
                    if (result != null) {
                        checkResults.add(result);
                    }
                }
            }
        }
        return checkResults;
    }

    /**
     * Checks the super classes or class annotations to figure out the platform, or null if nothing can be found
     */
    private Platform checkClassForPlatform(ClassNode classNode) {
        if (classNode.superName == null) {
            return null;
        }
        return switch (classNode.superName) {
            case "org/bukkit/plugin/java/JavaPlugin" -> Platform.PAPER;
            case "net/md_5/bungee/api/plugin/Plugin" -> Platform.WATERFALL;
            default -> {
                if (classNode.visibleAnnotations != null) {
                    for (AnnotationNode ann : classNode.visibleAnnotations) {
                        if (ann.desc.equals("Lcom/velocitypowered/api/plugin/Plugin;")) {
                            yield Platform.VELOCITY;
                        }
                    }
                }
                yield null;
            }
        };
    }
}

