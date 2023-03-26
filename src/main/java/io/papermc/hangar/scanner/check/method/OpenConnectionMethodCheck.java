package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class OpenConnectionMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if ((insnNode.name.equals("execute") || insnNode.name.equals("doExecute")) && insnNode.owner.contains("HttpClient")) {
            // apache http client
            return new MethodCheckResult(Severity.LOW, methodNode, classNode, "found open connection (apache) call");
        } else if (insnNode.name.equals("openConnection") && insnNode.owner.equals("java/net/URL")) {
            // URL.openConnection
            return new MethodCheckResult(Severity.LOW, methodNode, classNode, "found open connection (url) call");
        } else if (insnNode.name.equals("openStream") && insnNode.owner.equals("java/net/URL")) {
            // URL.openStream
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "found open stream (url) call");
        } else if (insnNode.name.equals("send") && insnNode.owner.equals("java/net/http/HttpClient")) {
            // jdk http client
            return new MethodCheckResult(Severity.LOW, methodNode, classNode, "found open connection (jdk http) call");
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 1;
    }
}
