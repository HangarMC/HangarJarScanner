package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.CheckResult.MethodCall;
import io.papermc.hangar.scanner.model.Severity;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CheckResultHasherTest {

    @Test
    void hashIsStableForIdenticalMethodCode() {
        MethodCall first = resultWithMethod(createMethodNode(false));
        MethodCall second = resultWithMethod(createMethodNode(false));

        assertEquals(first.hash(), second.hash());
    }

    @Test
    void hashChangesWhenMethodCodeChanges() {
        MethodCall first = resultWithMethod(createMethodNode(false));
        MethodCall second = resultWithMethod(createMethodNode(true));

        assertNotEquals(first.hash(), second.hash());
    }

    private static MethodCall resultWithMethod(MethodNode methodNode) {
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Example";
        classNode.methods = new ArrayList<>();
        classNode.methods.add(methodNode);
        return new MethodCall(Severity.HIGH, "Example check", 1, classNode, methodNode, new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "example/Service", "run", "()V", false), "matched call");
    }

    private static MethodNode createMethodNode(boolean changed) {
        MethodNode methodNode = new MethodNode();
        methodNode.name = "scan";
        methodNode.desc = "()V";
        methodNode.access = Opcodes.ACC_PUBLIC;
        methodNode.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        if (changed) {
            methodNode.instructions.add(new InsnNode(Opcodes.NOP));
        }
        methodNode.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "example/Service", "run", "()V", false));
        methodNode.instructions.add(new InsnNode(Opcodes.RETURN));
        return methodNode;
    }
}
