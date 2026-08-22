package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class TrollCheck implements Check {
    @Override
    public String name() {
        return "Troll";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("<init>") && insnNode.owner.endsWith("PacketPlayOutExplosion")) {
            return methodCallResult(context, Severity.MEDIUM, "creates fake explosion packet that can potentially be used to crash players");
        }
        return null;
    }
}
