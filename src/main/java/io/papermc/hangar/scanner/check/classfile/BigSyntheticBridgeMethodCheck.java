package io.papermc.hangar.scanner.check.classfile;

import io.papermc.hangar.scanner.check.ClassCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

public class BigSyntheticBridgeMethodCheck implements ClassCheck {

    private static final int MIN_INSTRUCTION_COUNT = 100;

    @Override
    public String name() {
        return "Big synthetic bridge method";
    }

    @Override
    public ClassCheckResult check(ClassNode classNode) {
        if (classNode.methods == null) {
            return null;
        }
        for (MethodNode methodNode : classNode.methods) {
            int instructionCount = instructionCount(methodNode);
            if (isSyntheticOrBridge(methodNode) && instructionCount >= MIN_INSTRUCTION_COUNT) {
                return new ClassCheckResult(
                        Severity.HIGHEST,
                        name(),
                        classNode,
                        "contains a synthetic/bridge method " + methodNode.name + methodNode.desc
                                + " with " + instructionCount + " instructions"
                );
            }
        }
        return null;
    }

    private static boolean isSyntheticOrBridge(MethodNode methodNode) {
        return (methodNode.access & (Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0;
    }

    private static int instructionCount(MethodNode methodNode) {
        int count = 0;
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction.getOpcode() >= 0) {
                count++;
            }
        }
        return count;
    }

    @Override
    public int updatedAt() {
        return 3;
    }
}
