package io.papermc.hangar.scanner.check;


import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

public sealed interface CheckResult {
    String name();

    String location();

    String message();

    Severity severity();

    int updatedAt();

    default String hash() {
        return CheckResultHasher.hash(this);
    }

    default String format() {
        return "[" + severity().name() + "]: [" + name() + "]: " + message() + " at " + location();
    }


    record Simple(Severity severity, String name, int updatedAt, String location, String message) implements CheckResult {

    }

    record Exception(Severity severity, String name, int updatedAt, String location, String message, java.lang.Exception exception) implements CheckResult {

    }

    record Class(Severity severity, String name, int updatedAt, ClassNode classNode, String message) implements CheckResult {
        @Override
        public String location() {
            return classNode.name;
        }
    }

    record Field(Severity severity, String name, int updatedAt, ClassNode classNode, FieldNode fieldNode, String message) implements CheckResult {
        @Override
        public String location() {
            return classNode.name + "#" + fieldNode.name;
        }
    }

    record Method(Severity severity, String name, int updatedAt, ClassNode classNode, MethodNode methodNode, String message) implements CheckResult {
        @Override
        public String location() {
            return classNode.name + "#" + methodNode.name + "(" + methodNode.desc + ")";
        }
    }

    record MethodCall(Severity severity, String name, int updatedAt, ClassNode classNode, MethodNode methodNode, MethodInsnNode methodInsnNode, String message) implements CheckResult {
        @Override
        public String location() {
            return methodInsnNode.owner + "#" + methodInsnNode.name + "(" + methodInsnNode.desc + ")" + " @ " + classNode.name  + "#" + methodNode.name + "(" + methodNode.desc + ")";
        }
    }
}
