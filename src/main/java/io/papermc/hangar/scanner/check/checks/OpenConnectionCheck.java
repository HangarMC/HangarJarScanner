package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class OpenConnectionCheck implements Check {
    @Override
    public String name() {
        return "Open connection method";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if ((insnNode.name.equals("execute") || insnNode.name.equals("doExecute")) && insnNode.owner.contains("HttpClient")) {
            return methodCallResult(context, Severity.LOW, "found open connection (apache) call");
        } else if (insnNode.name.equals("openConnection") && insnNode.owner.equals("java/net/URL")) {
            return methodCallResult(context, Severity.LOW, "found open connection (url) call");
        } else if (insnNode.name.equals("openStream") && insnNode.owner.equals("java/net/URL")) {
            return methodCallResult(context, Severity.MEDIUM, "found open stream (url) call");
        } else if (insnNode.name.equals("send") && insnNode.owner.equals("java/net/http/HttpClient")) {
            return methodCallResult(context, Severity.LOW, "found open connection (jdk http) call");
        }
        return null;
    }
}
