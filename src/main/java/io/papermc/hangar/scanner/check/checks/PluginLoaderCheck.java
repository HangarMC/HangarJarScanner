package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class PluginLoaderCheck implements Check {
    @Override
    public String name() {
        return "Plugin loader";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if ((insnNode.name.equals("loadPlugin") || insnNode.name.equals("enablePlugin")) && insnNode.owner.equals("org/bukkit/plugin/PluginManager")) {
            return methodCallResult(context, Severity.HIGH, "calls PluginManager." + insnNode.name);
        }
        return null;
    }
}
