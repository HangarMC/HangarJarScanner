package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class SystemPropertyMethodCheck implements MethodCheck {
    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        if (isSystemSetProperty(insnNode)) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "calls System.setProperty");
        } else if (isPutCall(insnNode) && hasRecentGetPropertiesCall(insnNode)) {
            return new MethodCheckResult(Severity.MEDIUM, methodNode, classNode, "calls System.getProperties().put/putAll");
        }

        return null;
    }

    private static boolean isSystemSetProperty(MethodInsnNode insnNode) {
        return "java/lang/System".equals(insnNode.owner)
               && "setProperty".equals(insnNode.name)
               && "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;".equals(insnNode.desc);
    }

    private static boolean isPutCall(MethodInsnNode insnNode) {
        return ("put".equals(insnNode.name) || "putAll".equals(insnNode.name))
               && "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;".equals(insnNode.desc)
               && (
                       "java/util/Properties".equals(insnNode.owner)
                       || "java/util/Hashtable".equals(insnNode.owner)
                       || "java/util/Map".equals(insnNode.owner)
               );
    }

    private static boolean hasRecentGetPropertiesCall(MethodInsnNode putInsnNode) {
        AbstractInsnNode cursor = putInsnNode.getPrevious();
        int scannedInstructions = 0;
        while (cursor != null && scannedInstructions < 12) {
            if (cursor instanceof MethodInsnNode methodInsnNode
                && "java/lang/System".equals(methodInsnNode.owner)
                && "getProperties".equals(methodInsnNode.name)
                && "()Ljava/util/Properties;".equals(methodInsnNode.desc)) {
                return true;
            }
            cursor = cursor.getPrevious();
            scannedInstructions++;
        }
        return false;
    }

    @Override
    public int updatedAt() {
        return 2;
    }
}
