package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class CheckContext {

    private Severity highestSeverity = Severity.UNKNOWN;

    private ClassNode classNode;
    private FieldNode fieldNode;
    private MethodNode methodNode;
    private MethodInsnNode methodCallNode;

    public ClassNode getClassNode() {
        return classNode;
    }

    public void setClassNode(ClassNode classNode) {
        this.classNode = classNode;
    }

    public FieldNode getFieldNode() {
        return fieldNode;
    }

    public void setFieldNode(FieldNode fieldNode) {
        this.fieldNode = fieldNode;
    }

    public MethodNode getMethodNode() {
        return methodNode;
    }

    public void setMethodNode(MethodNode methodNode) {
        this.methodNode = methodNode;
    }

    public MethodInsnNode getMethodCallNode() {
        return methodCallNode;
    }

    public void setMethodCallNode(MethodInsnNode methodCallNode) {
        this.methodCallNode = methodCallNode;
    }

    public Severity getHighestSeverity() {
        return highestSeverity;
    }

    public void updatedHighestSeverity(CheckResult result) {
        if (result == null) {
            return;
        }
        if (result.severity().compareTo(highestSeverity) < 0) {
            highestSeverity = result.severity();
        }
    }
}
