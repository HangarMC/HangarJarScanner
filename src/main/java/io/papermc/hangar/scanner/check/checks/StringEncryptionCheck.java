package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class StringEncryptionCheck implements Check {
    @Override
    public String name() {
        return "String encryption";
    }

    @Override
    public int updatedAt() {
        return 1;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("init") && insnNode.owner.equals("javax/crypto/Cipher")) {
            return methodCallResult(context, Severity.MEDIUM, "calls Cipher.init, an indicator for String Encryption");
        }
        return null;
    }
}
