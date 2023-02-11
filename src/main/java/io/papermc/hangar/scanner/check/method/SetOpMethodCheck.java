package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class SetOpMethodCheck implements MethodCheck {

    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("setOp")) {
            return new MethodCheckResult(Severity.HIGHEST, methodNode, classNode, "found setOp call");
        }
        if (insnNode.name.endsWith("getOperators") && insnNode.owner.equals("org/bukkit/Server")) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "found getOperators call");
        }
        return null;
    }
}
