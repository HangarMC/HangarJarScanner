package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;

public class SystemPropertyCheck implements Check {
    @Override
    public String name() {
        return "System property";
    }

    @Override
    public int updatedAt() {
        return 2;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (isSystemSetProperty(insnNode)) {
            return methodCallResult(context, Severity.MEDIUM, "calls System.setProperty");
        } else if (isPutCall(insnNode) && hasRecentGetPropertiesCall(insnNode)) {
            return methodCallResult(context, Severity.MEDIUM, "calls System.getProperties().put/putAll");
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
}
