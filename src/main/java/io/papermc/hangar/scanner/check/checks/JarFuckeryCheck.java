package io.papermc.hangar.scanner.check.checks;

import io.papermc.hangar.scanner.check.Check;
import io.papermc.hangar.scanner.check.CheckContext;
import io.papermc.hangar.scanner.check.CheckResult;
import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.MethodInsnNode;

public class JarFuckeryCheck implements Check {
    @Override
    public String name() {
        return "Jar fuckery";
    }

    @Override
    public int updatedAt() {
        return 2;
    }

    @Override
    public CheckResult.MethodCall checkMethodCall(CheckContext context, MethodInsnNode insnNode) {
        if (insnNode.name.equals("<init>")) {
            return switch (insnNode.owner) {
                case "java/util/jar/JarEntry" ->
                        methodCallResult(context, Severity.HIGH, "creates JarEntry");
                case "java/util/jar/JarFile" ->
                        methodCallResult(context, Severity.HIGH, "opens JarFile");
                case "java/util/jar/JarInputStream" ->
                        methodCallResult(context, Severity.HIGH, "opens JarInputStream");
                case "java/util/jar/JarOutputStream" ->
                        methodCallResult(context, Severity.HIGHEST, "opens JarOutputStream");
                default -> null;
            };
        }
        return null;
    }
}
