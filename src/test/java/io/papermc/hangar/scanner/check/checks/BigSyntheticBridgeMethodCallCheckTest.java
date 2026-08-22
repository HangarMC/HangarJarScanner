package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult.Method;
import io.papermc.hangar.scanner.model.Severity;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class BigSyntheticBridgeMethodCallCheckTest {

    private final BigSyntheticBridgeMethodCheck check = new BigSyntheticBridgeMethodCheck();

    @Test
    void flagsBigSyntheticBridgeMethods() {
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Test";
        MethodNode methodNode = createMethod(Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE, "bridgeMethod", 150);

        Method result = checkMethod(classNode, methodNode);

        assertNotNull(result);
        assertEquals(Severity.HIGHEST, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("synthetic/bridge method with 150 instructions", result.message());
    }

    @Test
    void ignoresSmallSyntheticBridgeMethods() {
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Test";
        MethodNode methodNode = createMethod(Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE, "bridgeMethod", 8);

        Method result = checkMethod(classNode, methodNode);

        assertNull(result);
    }

    private Method checkMethod(ClassNode classNode, MethodNode methodNode) {
        CheckContext context = new CheckContext();
        context.setClassNode(classNode);
        context.setMethodNode(methodNode);
        return check.checkMethod(context, methodNode);
    }

    private static MethodNode createMethod(int access, String name, int instructionCount) {
        MethodNode methodNode = new MethodNode(access, name, "()V", null, null);
        for (int i = 0; i < instructionCount; i++) {
            methodNode.instructions.add(new InsnNode(Opcodes.NOP));
        }
        return methodNode;
    }
}
