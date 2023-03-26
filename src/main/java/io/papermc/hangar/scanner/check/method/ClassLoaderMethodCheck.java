package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class ClassLoaderMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("<init>") && insnNode.owner.equals("java/net/URLClassLoader")) {
            return new MethodCheckResult(Severity.HIGH, methodNode, classNode, "creates new URLClassLoader");
        }
        if (insnNode.name.equals("forName") && insnNode.owner.equals("java/lang/Class")) {
            return new MethodCheckResult(Severity.LOW, methodNode, classNode, "calls Class.forName");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
