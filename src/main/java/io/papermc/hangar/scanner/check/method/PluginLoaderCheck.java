package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class PluginLoaderCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if ((insnNode.name.equals("loadPlugin") || insnNode.name.equals("enablePlugin")) && insnNode.owner.equals("org/bukkit/plugin/PluginManager")) {
           return new MethodCheckResult(Severity.HIGH, methodNode, classNode, "calls PluginManager." + insnNode.name);
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
