package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class StringEncryptionCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (insnNode.name.equals("init") && insnNode.owner.equals("javax/crypto/Cipher")) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "calls Cipher.init, an indicator for String Encryption");
        }
        if (insnNode.name.equals("getInstance") && insnNode.owner.equals("javax/crypto/Cipher")) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "calls Cipher.getInstance, an indicator for String Encryption");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
