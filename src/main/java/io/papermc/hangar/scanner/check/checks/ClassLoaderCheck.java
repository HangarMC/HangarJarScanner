package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class ClassLoaderCheck implements Check {

    @Override
    public String name() {
        return "Class loader method";
    }

    @Override
    public int updatedAt() {
        return 5;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("<init>") && insnNode.owner.equals("java/net/URLClassLoader")) {
            return methodCallResult(context, Severity.HIGH, "creates new URLClassLoader");
        }
        if (insnNode.name.equals("<init>") && insnNode.owner.equals("java/lang/ClassLoader")) {
            return methodCallResult(context, Severity.HIGH, "creates new ClassLoader");
        }
        if (insnNode.name.equals("forName") && insnNode.owner.equals("java/lang/Class")) {
            return methodCallResult(context, Severity.LOW, "calls Class.forName");
        }
        return null;
    }
}
