package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class JarFuckeryCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("<init>")) {
            return switch (insnNode.owner) {
                case "java/util/jar/JarEntry" ->
                        new MethodCheckResult(Severity.HIGH, methodNode, classNode, "creates JarEntry");
                case "java/util/jar/JarFile" ->
                        new MethodCheckResult(Severity.HIGH, methodNode, classNode, "opens JarFile");
                case "java/util/jar/JarInputStream" ->
                        new MethodCheckResult(Severity.HIGH, methodNode, classNode, "opens JarInputStream");
                case "java/util/jar/JarOutputStream" ->
                        new MethodCheckResult(Severity.HIGHEST, methodNode, classNode, "opens JarOutputStream");
                default -> null;
            };
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 2;
    }
}
