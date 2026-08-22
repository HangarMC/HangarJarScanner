package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult.MethodCall;
import io.papermc.hangar.scanner.model.Severity;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RuntimeDiagnosticsCheckTest {

    private final RuntimeDiagnosticsCheck check = new RuntimeDiagnosticsCheck();

    @Test
    void flagsManagementFactoryRuntimeMxBeanAccess() {
        MethodCall result = checkMethodCall(new MethodInsnNode(0, "java/lang/management/ManagementFactory", "getRuntimeMXBean", "()Ljava/lang/management/RuntimeMXBean;", false));

        assertNotNull(result);
        assertEquals(Severity.MEDIUM, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("calls ManagementFactory.getRuntimeMXBean", result.message());
    }

    @Test
    void flagsRuntimeGetRuntimeAccess() {
        MethodCall result = checkMethodCall(new MethodInsnNode(0, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false));

        assertNotNull(result);
        assertEquals(Severity.MEDIUM, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("calls Runtime.getRuntime", result.message());
    }

    private MethodCall checkMethodCall(MethodInsnNode methodInsnNode) {
        CheckContext context = new CheckContext();
        ClassNode classNode = new ClassNode();
        classNode.name = "example/Example";
        context.setClassNode(classNode);
        MethodNode methodNode = new MethodNode();
        methodNode.name = "scan";
        methodNode.desc = "()V";
        context.setMethodNode(methodNode);
        return check.checkMethodCall(context, methodInsnNode);
    }
}
