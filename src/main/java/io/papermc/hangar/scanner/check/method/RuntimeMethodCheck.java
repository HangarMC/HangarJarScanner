package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class RuntimeMethodCheck implements MethodCheck {
    @Override
    public String name() {
        return "Runtime diagnostics";
    }

    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.owner.equals("java/lang/management/ManagementFactory") && insnNode.name.equals("getRuntimeMXBean")) {
            return new MethodCheckResult(Severity.MEDIUM, name(), methodNode, classNode, "calls ManagementFactory.getRuntimeMXBean");
        }

        if (insnNode.owner.equals("java/lang/Runtime") && insnNode.name.equals("getRuntime")) {
            return new MethodCheckResult(Severity.MEDIUM, name(), methodNode, classNode, "calls Runtime.getRuntime");
        }

        if (insnNode.owner.equals("java/lang/management/RuntimeMXBean")) {
            return new MethodCheckResult(Severity.MEDIUM, name(), methodNode, classNode, "calls RuntimeMXBean." + insnNode.name);
        }

        return null;
    }

    @Override
    public int updatedAt() {
        return 2;
    }
}
