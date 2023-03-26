package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class ThreadSleepMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("sleep") && insnNode.owner.equals("java/lang/Thread") && insnNode.desc.equals("(J)V")) {
            return new MethodCheckResult(Severity.LOW, methodNode, classNode, "found Thread.sleep call");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
