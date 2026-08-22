package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class RuntimeDiagnosticsCheck implements Check {
    @Override
    public String name() {
        return "Runtime diagnostics";
    }

    @Override
    public int updatedAt() {
        return 2;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.owner.equals("java/lang/management/ManagementFactory") && insnNode.name.equals("getRuntimeMXBean")) {
            return methodCallResult(context, Severity.MEDIUM, "calls ManagementFactory.getRuntimeMXBean");
        }

        if (insnNode.owner.equals("java/lang/Runtime") && insnNode.name.equals("getRuntime")) {
            return methodCallResult(context, Severity.MEDIUM, "calls Runtime.getRuntime");
        }

        if (insnNode.owner.equals("java/lang/management/RuntimeMXBean")) {
            return methodCallResult(context, Severity.MEDIUM, "calls RuntimeMXBean." + insnNode.name);
        }

        return null;
    }
}
