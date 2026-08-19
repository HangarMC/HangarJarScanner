package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.model.Severity;
import org.objectweb.asm.tree.ClassNode;

public interface ClassCheck extends Check {
    ClassCheckResult check(ClassNode classNode);

    record ClassCheckResult(Severity severity, String name, ClassNode classNode, String message) implements CheckResult {
        @Override
        public String location() {
            return classNode.name;
        }
    }
}
