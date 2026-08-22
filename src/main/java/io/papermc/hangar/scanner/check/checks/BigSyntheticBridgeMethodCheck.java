package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class BigSyntheticBridgeMethodCheck implements Check {

    private static final int MIN_INSTRUCTION_COUNT = 100;

    @Override
    public String name() {
        return "Big synthetic bridge method";
    }

    @Override
    public int updatedAt() {
        return 3;
    }

    @Override
    public CheckResult.Method checkMethod(CheckContext context, MethodNode methodNode) {
        int instructionCount = instructionCount(methodNode);
        if (isSyntheticOrBridge(methodNode) && instructionCount >= MIN_INSTRUCTION_COUNT) {
            return methodResult(context, Severity.HIGHEST, "synthetic/bridge method with " + instructionCount + " instructions");
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
}
