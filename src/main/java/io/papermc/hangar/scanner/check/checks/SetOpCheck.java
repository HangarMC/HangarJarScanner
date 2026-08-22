package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class SetOpCheck implements Check {

    @Override
    public String name() {
        return "Set op";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("setOp") && (insnNode.owner.startsWith("org/bukkit"))) {
            return methodCallResult(context, Severity.HIGHEST, "found setOp call");
        }
        if (insnNode.name.endsWith("getOperators") && insnNode.owner.equals("org/bukkit/Server")) {
            return methodCallResult(context, Severity.MEDIUM, "found getOperators call");
        }
        return null;
    }
}
