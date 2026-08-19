package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck.MethodCheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RuntimeMethodCheckTest {

    private final RuntimeMethodCheck check = new RuntimeMethodCheck();

    @Test
    void flagsManagementFactoryRuntimeMxBeanAccess() {
        MethodCheckResult result = check.check(
                new MethodInsnNode(0, "java/lang/management/ManagementFactory", "getRuntimeMXBean", "()Ljava/lang/management/RuntimeMXBean;", false),
                new MethodNode(),
                new ClassNode()
        );

        assertNotNull(result);
        assertEquals(Severity.MEDIUM, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("calls ManagementFactory.getRuntimeMXBean", result.message());
    }

    @Test
    void flagsRuntimeGetRuntimeAccess() {
        MethodCheckResult result = check.check(
                new MethodInsnNode(0, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false),
                new MethodNode(),
                new ClassNode()
        );

        assertNotNull(result);
        assertEquals(Severity.MEDIUM, result.severity());
        assertEquals(check.name(), result.name());
        assertEquals("calls Runtime.getRuntime", result.message());
    }
}
