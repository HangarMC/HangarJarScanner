package io.papermc.hangar.scanner.check.classfile;

import io.papermc.hangar.scanner.check.ClassCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

public class StringLiteralSubstringCheck implements ClassCheck {

    private static final String[] bannedSubstrings = new String[] {"notme"};

    @Override
    public String name() {
        return "Banned String literal substring";
    }

    @Override
    public ClassCheckResult check(ClassNode classNode) {
        for (FieldNode fieldNode : classNode.fields) {
            String banned = findBannedSubstring(fieldNode);
            if (banned != null) {
                return new ClassCheckResult(Severity.HIGHEST, name(), classNode, "contains banned string literal substring '" + banned + "' in field " + fieldNode.name);
            }
        }
        for (MethodNode methodNode : classNode.methods) {
            var banned = findBannedSubstring(methodNode);
            if (banned != null) {
                return new ClassCheckResult(Severity.HIGHEST, name(), classNode, "contains banned string literal substring '" + banned + "' in method " + methodNode.name);
            }
        }
        return null;
    }

    private String findBannedSubstring(MethodNode methodNode) {
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction instanceof LdcInsnNode ldcInsnNode
                    && ldcInsnNode.cst instanceof String stringLiteral) {
                for (String bannedSubstring : bannedSubstrings) {
                    if (stringLiteral.contains(bannedSubstring)) {
                        return bannedSubstring;
                    }
                }
            }
        }
        return null;
    }

    private String findBannedSubstring(FieldNode fieldNode) {
        if (fieldNode.value instanceof String stringLiteral) {
            for (String bannedSubstring : bannedSubstrings) {
                if (stringLiteral.contains(bannedSubstring)) {
                    return bannedSubstring;
                }
            }
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 3;
    }
}
