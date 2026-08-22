package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class DispatchCommandCheck implements Check {

    @Override
    public String name() {
        return "Dispatch command";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("dispatchCommand") && insnNode.owner.equals("org/bukkit/Bukkit")) {
            return methodCallResult(context, Severity.HIGH, "calls Bukkit.dispatchCommand");
        }
        if (insnNode.name.equals("dispatchCommand") && insnNode.owner.equals("org/bukkit/Server")) {
            return methodCallResult(context, Severity.HIGH, "calls Server.dispatchCommand");
        }
        if (insnNode.name.equals("performCommand") && insnNode.owner.equals("org/bukkit/entity/Player")) {
            return methodCallResult(context, Severity.HIGH, "calls Player.performCommand");
        }
        if (insnNode.name.equals("chat") && insnNode.owner.equals("org/bukkit/entity/Player")) {
            return methodCallResult(context, Severity.HIGH, "calls Player.chat that can also be used to perform commands");
        }
        return null;
    }
}
