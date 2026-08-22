package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public interface Check {

    String name();

    /**
     * Returns the last internal scanner version the check was updated in.
     *
     * @return last internal scanner version the check was updated in
     */
    int updatedAt();

    default CheckResult.Class checkClass(CheckContext context, ClassNode classNode) {
        return null;
    }

    default CheckResult.Field checkField(CheckContext context, FieldNode fieldNode) {
        return null;
    }

    default CheckResult.Method checkMethod(CheckContext context, MethodNode methodNode)  {
        return null;
    }

    default CheckResult checkMethodCall(CheckContext context, MethodInsnNode methodInsnNode) {
        return null;
    }

    default CheckResult.Class classResult(CheckContext context, Severity severity, String message) {
        return new CheckResult.Class(severity, name(), updatedAt(), context.getClassNode(), message);
    }

    default CheckResult.Field fieldResult(CheckContext context, Severity severity, String message) {
        return new CheckResult.Field(severity, name(), updatedAt(), context.getClassNode(), context.getFieldNode(), message);
    }

    default CheckResult.Method methodResult(CheckContext context, Severity severity, String message) {
        return new CheckResult.Method(severity, name(), updatedAt(), context.getClassNode(), context.getMethodNode(), message);
    }

    default CheckResult.MethodCall methodCallResult(CheckContext context, Severity severity, String message) {
        return new CheckResult.MethodCall(severity, name(), updatedAt(), context.getClassNode(), context.getMethodNode(), context.getMethodCallNode(), message);
    }
}
