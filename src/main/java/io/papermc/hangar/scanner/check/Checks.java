package io.papermc.hangar.scanner.check;

import io.papermc.hangar.scanner.check.checks.*;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.*;

public class Checks {

    static List<Check> checks = List.of(
            new ByteArrayLiteralCheck(),
            new BannedWordCheck(),
            new BigSyntheticBridgeMethodCheck(),
            new ClassLoaderCheck(),
            new OpenConnectionCheck(),
            new SetOpCheck(),
            new ThreadSleepCheck(),
            new PluginLoaderCheck(),
            new SocketCheck(),
            new StringEncryptionCheck(),
            new DispatchCommandCheck(),
            new ExecMethodCheck(),
            new RuntimeDiagnosticsCheck(),
            new TrollCheck(),
            new JarFuckeryCheck(),
            new SystemPropertyCheck()
    );

    public static Set<CheckResult> checkClass(CheckContext context, ClassNode classNode) {
        Set<CheckResult> checkResults = new LinkedHashSet<>();
        for (Check check : checks) {
            CheckResult result = check.checkClass(context, classNode);
            if (result != null) {
                context.updatedHighestSeverity(result);
                checkResults.add(result);
            }
        }
        return checkResults;
    }

    public static Set<CheckResult> checkMethod(CheckContext context, MethodNode methodNode) {
        Set<CheckResult> checkResults = new LinkedHashSet<>();
        for (Check check : checks) {
            CheckResult result = check.checkMethod(context, methodNode);
            if (result != null) {
                context.updatedHighestSeverity(result);
                checkResults.add(result);
            }
        }
        return checkResults;
    }

    public static Set<CheckResult> checkField(CheckContext context, FieldNode fieldNode) {
        Set<CheckResult> checkResults = new LinkedHashSet<>();
        for (Check check : checks) {
            CheckResult result = check.checkField(context, fieldNode);
            if (result != null) {
                context.updatedHighestSeverity(result);
                checkResults.add(result);
            }
        }
        return checkResults;
    }

    public static Set<CheckResult> checkMethodCall(CheckContext context, MethodInsnNode methodInsnNode) {
        Set<CheckResult> checkResults = new LinkedHashSet<>();
        for (Check check : checks) {
            CheckResult result = check.checkMethodCall(context, methodInsnNode);
            if (result != null) {
                context.updatedHighestSeverity(result);
                checkResults.add(result);
            }
        }
        return checkResults;
    }
}
