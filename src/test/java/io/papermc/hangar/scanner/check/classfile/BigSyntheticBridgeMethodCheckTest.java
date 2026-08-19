package io.papermc.hangar.scanner.check.classfile;

import io.papermc.hangar.scanner.check.ClassCheck.ClassCheckResult;
import io.papermc.hangar.scanner.model.Severity;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class BigSyntheticBridgeMethodCheckTest {

    private final BigSyntheticBridgeMethodCheck check = new BigSyntheticBridgeMethodCheck();

    @Test
    void flagsBigSyntheticBridgeMethods() {
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Test";
        classNode.methods = new ArrayList<>();
        classNode.methods.add(createMethod(Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE, "bridgeMethod", 150));

        ClassCheckResult result = check.check(classNode);

        assertNotNull(result);
        assertEquals(Severity.HIGHEST, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("contains a synthetic/bridge method bridgeMethod()V with 150 instructions", result.message());
    }

    @Test
    void ignoresSmallSyntheticBridgeMethods() {
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Test";
        classNode.methods = new ArrayList<>();
        classNode.methods.add(createMethod(Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE, "bridgeMethod", 8));

        ClassCheckResult result = check.check(classNode);

        assertNull(result);
    }

    private static MethodNode createMethod(int access, String name, int instructionCount) {
        MethodNode methodNode = new MethodNode(access, name, "()V", null, null);
        for (int i = 0; i < instructionCount; i++) {
            methodNode.instructions.add(new InsnNode(Opcodes.NOP));
        }
        return methodNode;
    }
}
