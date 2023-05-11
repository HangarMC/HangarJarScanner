package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class InetSocketMethodCheck implements MethodCheck {
    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("<init>") && insnNode.owner.equals("java/net/InetSocketAddress")) {
            return new MethodCheckResult(Severity.HIGH, methodNode, classNode, "defines a socket to connect to a server");
        }
        return null;
    }
}
