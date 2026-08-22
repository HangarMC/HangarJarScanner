package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class ExecMethodCheck implements Check {

    @Override
    public String name() {
        return "Exec method";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("exec") && insnNode.owner.equals("java/lang/Runtime")) {
            return methodCallResult(context, Severity.HIGHEST, "calls Runtime.exec");
        }
        return null;
    }
}
