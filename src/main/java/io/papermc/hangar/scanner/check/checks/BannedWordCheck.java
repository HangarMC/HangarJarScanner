package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.*;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.*;

import java.util.Locale;

public class BannedWordCheck implements Check {

    private static final String[] bannedSubstrings = new String[]{"notme", "xmrig"};

    @Override
    public String name() {
        return "Banned String literal substring";
    }

    @Override
    public int updatedAt() {
        return 3;
    }

    @Override
    public CheckResult.Field checkField(CheckContext context, FieldNode fieldNode) {
        String lowerCaseName = fieldNode.name.toLowerCase(Locale.ROOT);
        for (String bannedSubstring : bannedSubstrings) {
            if (lowerCaseName.contains(bannedSubstring)) {
                return fieldResult(context, Severity.HIGHEST, "contains banned string literal substring '" + bannedSubstring + "' in field name");
            }
        }

        String banned = findBannedSubstring(fieldNode);
        if (banned != null) {
            return fieldResult(context, Severity.HIGHEST, "contains banned string literal substring '" + banned + "'");
        }
        return null;
    }

    @Override
    public CheckResult.Method checkMethod(CheckContext context, MethodNode methodNode) {
        String lowerCaseName = methodNode.name.toLowerCase(Locale.ROOT);
        for (String bannedSubstring : bannedSubstrings) {
            if (lowerCaseName.contains(bannedSubstring)) {
                return methodResult(context, Severity.HIGHEST, "contains banned string literal substring '" + bannedSubstring + "' in method name");
            }
        }

        String banned = findBannedSubstring(methodNode);
        if (banned != null) {
            return methodResult(context, Severity.HIGHEST, "contains banned string literal substring '" + banned + "'");
        }
        return null;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode methodInsnNode) {
        String banned = findBannedSubstring(methodInsnNode);
        if (banned != null) {
            return methodCallResult(context, Severity.HIGHEST, "calls method with banned word " + banned);
        }
        return null;
    }

    private String findBannedSubstring(MethodNode methodNode) {
        for (AbstractInsnNode instruction : methodNode.instructions) {
            if (instruction instanceof LdcInsnNode ldcInsnNode
                && ldcInsnNode.cst instanceof String stringLiteral) {
                String lowerCase = stringLiteral.toLowerCase(Locale.ROOT);
                for (String bannedSubstring : bannedSubstrings) {
                    if (lowerCase.contains(bannedSubstring)) {
                        return bannedSubstring;
                    }
                }
            }
        }
        return null;
    }

    private String findBannedSubstring(FieldNode fieldNode) {
        if (fieldNode.value instanceof String stringLiteral) {
            String lowerCase = stringLiteral.toLowerCase(Locale.ROOT);
            for (String bannedSubstring : bannedSubstrings) {
                if (lowerCase.contains(bannedSubstring)) {
                    return bannedSubstring;
                }
            }
        }
        return null;
    }

    private String findBannedSubstring(MethodInsnNode methodCallNode) {
        String lowerCase = methodCallNode.name.toLowerCase(Locale.ROOT);
        for (String bannedSubstring : bannedSubstrings) {
            if (lowerCase.contains(bannedSubstring)) {
                return bannedSubstring;
            }
        }
        return null;
    }
}
