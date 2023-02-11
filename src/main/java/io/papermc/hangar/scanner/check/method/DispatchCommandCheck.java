package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class DispatchCommandCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("dispatchCommand") && insnNode.owner.equals("org/bukkit/Bukkit")) {
            return new MethodCheckResult(Severity.HIGH, methodNode, classNode, "calls Bukkit.dispatchCommand");
        }
        if (insnNode.name.equals("dispatchCommand") && insnNode.owner.equals("org/bukkit/Server")) {
            return new MethodCheckResult(Severity.HIGH, methodNode, classNode, "calls Server.dispatchCommand");
        }
        return null;
    }
}
