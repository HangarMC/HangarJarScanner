package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class TrollMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("<init>") && insnNode.owner.endsWith("PacketPlayOutExplosion")) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "creates fake explosion packet than can potentially be used to crash players");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
