package io.papermc.hangar.scanner;

import io.papermc.hangar.scanner.check.*;
import io.papermc.hangar.scanner.model.ScanResult;
import io.papermc.hangar.scanner.model.Severity;
import io.papermc.hangar.scanner.util.JarUtil;
import io.papermc.hangar.scanner.util.JarUtil.Jar;

import java.io.InputStream;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.jar.JarEntry;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.*;

public class HangarJarScanner {

    public ScanResult scanJar(InputStream stream, String name) {
        Set<CheckResult> checkResults = new LinkedHashSet<>();
        CheckContext context = new CheckContext();
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

                    checkResults.addAll(scanClazz(context, bytes, jarEntry.getName()));

                    if (!jarEntry.getName().endsWith(".class")) {
                        checkResults.add(scannerResult(context, jarEntry.getName(), "disguised class file, starts with 0xCAFEBABE"));
                    }
                } else if (jarEntry.getName().endsWith(".class")) {
                    checkResults.add(scannerResult(context, jarEntry.getName(), ".class file without 0xCAFEBABE"));
                } else if (magic.startsWith("7F454C")) { // ELF magic
                    checkResults.add(scannerResult(context, jarEntry.getName(), "disguised linux executable binary file, starts with 0x7F454C (ELF)"));
                }
            }
        } catch (Exception ex) {
            CheckResult result = new CheckResult.Exception(Severity.HIGHEST, "Scanner", version(), name, "Crashes while scanning with " + ex.getClass().getName() + ": " + ex.getMessage(), ex);
            context.updatedHighestSeverity(result);
            checkResults.add(result);
        }
        return new ScanResult(context.getHighestSeverity(), checkResults);
    }

    private CheckResult scannerResult(CheckContext context, String className, String message) {
        CheckResult result = new CheckResult.Simple(Severity.HIGHEST, "Scanner", version(), className, message);
        context.updatedHighestSeverity(result);
        return result;
    }

    public Set<CheckResult> scanClazz(CheckContext context, byte[] bytes, String name) {
        ClassReader cr = new ClassReader(bytes);
        ClassNode cn = new ClassNode();
        try {
            cr.accept(cn, ClassReader.EXPAND_FRAMES);
        } catch (Exception e) {
            throw new RuntimeException("Failed to read class " + name + " with ASM", e);
        }

        context.setClassNode(cn);
        Set<CheckResult> result = scan(context, cn);
        context.setClassNode(null);
        return result;
    }

    private Set<CheckResult> scan(CheckContext context, ClassNode cn) {
        Set<CheckResult> checkResults = new LinkedHashSet<>(Checks.checkClass(context, cn));
        for (MethodNode method : cn.methods) {
            context.setMethodNode(method);
            checkResults.addAll(scan(context, method));
            context.setMethodNode(null);
        }
        for (FieldNode field : cn.fields) {
            context.setFieldNode(field);
            checkResults.addAll(Checks.checkField(context, field));
            context.setFieldNode(null);
        }
        return checkResults;
    }

    private Set<CheckResult> scan(CheckContext context, MethodNode methodNode) {
        Set<CheckResult> checkResults = new LinkedHashSet<>(Checks.checkMethod(context, methodNode));
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction instanceof MethodInsnNode methodInsnNode) {
                context.setMethodCallNode(methodInsnNode);
                checkResults.addAll(Checks.checkMethodCall(context, methodInsnNode));
                context.setMethodCallNode(null);
            }
        }
        return checkResults;
    }

    /**
     * Returns the internal version of the scanner. Files should be rescanned if this version changes.
     *
     * @return the internal version of the scanner
     */
    public int version() {
        return 4;
    }
}
