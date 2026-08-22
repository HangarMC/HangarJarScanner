package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class ByteArrayLiteralCheck implements Check {

    @Override
    public String name() {
        return "Byte array literal";
    }

    @Override
    public int updatedAt() {
        return 2;
    }

    @Override
    public CheckResult.Method checkMethod(CheckContext context, MethodNode methodNode) {
        if (containsByteArrayLiteral(methodNode)) {
            return methodResult(context, Severity.MEDIUM, "creates byte array literal, an indicator for string encryption");
        }
        return null;
    }

    private static boolean containsByteArrayLiteral(MethodNode methodNode) {
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction instanceof IntInsnNode intInsnNode
                    && intInsnNode.getOpcode() == Opcodes.NEWARRAY
                    && intInsnNode.operand == Opcodes.T_BYTE
                    && hasLiteralStoresAfterNewArray(instruction)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasLiteralStoresAfterNewArray(AbstractInsnNode newArrayInstruction) {
        int stores = 0;
        AbstractInsnNode cursor = newArrayInstruction.getNext();
        while (cursor != null && stores < 32) {
            if (cursor.getOpcode() == Opcodes.BASTORE && hasRecentLiteralArraySetup(cursor)) {
                return true;
            }
            cursor = cursor.getNext();
            stores++;
        }
        return false;
    }

    private static boolean hasRecentLiteralArraySetup(AbstractInsnNode bastoreInstruction) {
        AbstractInsnNode cursor = bastoreInstruction.getPrevious();
        int scannedInstructions = 0;
        int integerConstants = 0;
        boolean sawDup = false;

        while (cursor != null && scannedInstructions < 8) {
            if (cursor.getOpcode() == Opcodes.DUP) {
                sawDup = true;
            } else if (isIntegerConstant(cursor)) {
                integerConstants++;
            } else if (cursor instanceof IntInsnNode intInsnNode
                    && intInsnNode.getOpcode() == Opcodes.NEWARRAY
                    && intInsnNode.operand == Opcodes.T_BYTE) {
                return sawDup && integerConstants >= 2;
            }

            cursor = cursor.getPrevious();
            scannedInstructions++;
        }

        return false;
    }

    private static boolean isIntegerConstant(AbstractInsnNode instruction) {
        int opcode = instruction.getOpcode();
        return opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5
                || opcode == Opcodes.BIPUSH
                || opcode == Opcodes.SIPUSH
                || instruction instanceof LdcInsnNode ldcInsnNode && ldcInsnNode.cst instanceof Integer;
    }
}
