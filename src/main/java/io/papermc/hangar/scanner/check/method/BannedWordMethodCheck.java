package io.papermc.hangar.scanner.check.method;

import io.papermc.hangar.scanner.check.MethodCheck;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.Locale;

public class BannedWordMethodCheck implements MethodCheck {

    private static final String[] bannedWords = new String[]{"xmrig"};

    @Override
    public MethodCheckResult check(MethodInsnNode insnNode, MethodNode methodNode, ClassNode classNode) {
        for (String bannedWord : bannedWords) {
            if (insnNode.name.toLowerCase(Locale.ROOT).contains(bannedWord)) {
                return new MethodCheckResult(Severity.HIGHEST, methodNode, classNode, "calls method with banned word " + bannedWord + ": " + insnNode.name);
            } else if (methodNode.name.toLowerCase(Locale.ROOT).contains(bannedWord)) {
                return new MethodCheckResult(Severity.HIGHEST, methodNode, classNode, "method contains banned word " + bannedWord);
            }
        }
        return null;
    }

    @Override
    public int updatedAt() {
        return 2;
    }
}
