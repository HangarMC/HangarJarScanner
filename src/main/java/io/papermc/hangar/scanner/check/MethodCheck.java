package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public interface MethodCheck extends Check {
    MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode);

    record MethodCheckResult(Severity severity, MethodNode methodNode, ClassNode classNode, String message) implements CheckResult {

        @Override
        public String location() {
            return methodNode.name + methodNode.desc + " @ " + classNode.name;
        }
    }
}
