package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class ExecMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("exec") && insnNode.owner.equals("java/lang/Runtime")) {
            return new MethodCheckResult(Severity.HIGHEST, methodNode, classNode, "calls Runtime.exec");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
