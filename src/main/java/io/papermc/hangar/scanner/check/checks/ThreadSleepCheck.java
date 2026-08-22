package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class ThreadSleepCheck implements Check {
    @Override
    public String name() {
        return "Thread sleep";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("sleep") && insnNode.owner.equals("java/lang/Thread") && insnNode.desc.equals("(J)V")) {
            return methodCallResult(context, Severity.LOW, "found Thread.sleep call");
        }
        return null;
    }
}
