package io.papermc.hangar.scanner.check;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Consumer;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

public final class CheckResultHasher {

    private CheckResultHasher() {
    }

    public static String hash(CheckResult result) {
        MessageDigest digest = newDigest();
        append(digest, result.severity().name());
        append(digest, result.name());
        append(digest, result.location());
        append(digest, result.message());
        append(digest, result.updatedAt());

        switch (result) {
            case CheckResult.Simple simpleCheckResult -> {
                append(digest, "simple");
            }
            case CheckResult.Exception exceptionCheckResult -> {
                append(digest, exceptionCheckResult.exception().getClass().getName());
                append(digest, String.valueOf(exceptionCheckResult.exception().getMessage()));
            }
            case CheckResult.Class classCheckResult -> {
                append(digest, fingerprint(classCheckResult.classNode()));
            }
            case CheckResult.Method methodCheckResult -> {
                append(digest, fingerprint(methodCheckResult.classNode()));
                append(digest, fingerprint(methodCheckResult.methodNode()));
            }
            case CheckResult.MethodCall methodCallCheckResult -> {
                append(digest, fingerprint(methodCallCheckResult.classNode()));
                append(digest, fingerprint(methodCallCheckResult.methodNode()));
                append(digest, fingerprint(methodCallCheckResult.methodInsnNode()));
            }
            default -> {
                append(digest, result.getClass().getName());
            }
        }
        return hex(digest.digest());
    }

    private static String fingerprint(ClassNode classNode) {
        MessageDigest digest = newDigest();
        append(digest, classNode.name);
        append(digest, classNode.access);
        append(digest, classNode.superName);
        append(digest, classNode.signature);
        append(digest, classNode.outerClass);
        append(digest, classNode.outerMethod);
        append(digest, classNode.outerMethodDesc);
        appendIterable(digest, classNode.interfaces);
        appendIterable(digest, classNode.fields, fieldNode -> append(digest, fingerprint(fieldNode)));
        appendIterable(digest, classNode.methods, methodNode -> append(digest, fingerprint(methodNode)));
        return hex(digest.digest());
    }

    private static String fingerprint(MethodNode methodNode) {
        MessageDigest digest = newDigest();
        append(digest, methodNode.name);
        append(digest, methodNode.desc);
        append(digest, methodNode.access);
        append(digest, methodNode.signature);
        appendIterable(digest, methodNode.exceptions);
        append(digest, methodNode.maxStack);
        append(digest, methodNode.maxLocals);
        appendInstructions(digest, methodNode.instructions);
        return hex(digest.digest());
    }

    private static String fingerprint(MethodInsnNode methodInsnNode) {
        MessageDigest digest = newDigest();
        append(digest, methodInsnNode.owner);
        append(digest, methodInsnNode.name);
        append(digest, methodInsnNode.desc);
        append(digest, methodInsnNode.itf);
        return hex(digest.digest());
    }

    private static String fingerprint(FieldNode fieldNode) {
        MessageDigest digest = newDigest();
        append(digest, fieldNode.name);
        append(digest, fieldNode.desc);
        append(digest, fieldNode.access);
        append(digest, fieldNode.signature);
        append(digest, fieldNode.value == null ? null : fieldNode.value.toString());
        return hex(digest.digest());
    }

    private static void appendInstructions(MessageDigest digest, InsnList instructions) {
        if (instructions == null) {
            append(digest, "<no-instructions>");
            return;
        }
        List<LabelNode> labels = new java.util.ArrayList<>();
        for (AbstractInsnNode instruction : instructions) {
            if (instruction instanceof LabelNode labelNode) {
                labels.add(labelNode);
            }
        }

        for (AbstractInsnNode instruction : instructions) {
            if (instruction instanceof LabelNode || instruction instanceof LineNumberNode || instruction instanceof FrameNode) {
                continue;
            }

            append(digest, instruction.getType());
            append(digest, instruction.getOpcode());

            if (instruction instanceof InsnNode) {
                continue;
            }
            if (instruction instanceof VarInsnNode varInsnNode) {
                append(digest, varInsnNode.var);
            } else if (instruction instanceof IntInsnNode intInsnNode) {
                append(digest, intInsnNode.operand);
            } else if (instruction instanceof TypeInsnNode typeInsnNode) {
                append(digest, typeInsnNode.desc);
            } else if (instruction instanceof FieldInsnNode fieldInsnNode) {
                append(digest, fieldInsnNode.owner);
                append(digest, fieldInsnNode.name);
                append(digest, fieldInsnNode.desc);
            } else if (instruction instanceof MethodInsnNode methodInsnNode) {
                append(digest, methodInsnNode.owner);
                append(digest, methodInsnNode.name);
                append(digest, methodInsnNode.desc);
                append(digest, methodInsnNode.itf);
            } else if (instruction instanceof InvokeDynamicInsnNode invokeDynamicInsnNode) {
                append(digest, invokeDynamicInsnNode.name);
                append(digest, invokeDynamicInsnNode.desc);
                appendHandle(digest, invokeDynamicInsnNode.bsm);
                appendIterable(digest, Arrays.asList(invokeDynamicInsnNode.bsmArgs), arg -> appendValue(digest, arg));
            } else if (instruction instanceof JumpInsnNode jumpInsnNode) {
                append(digest, labelIndex(labels, jumpInsnNode.label));
            } else if (instruction instanceof LdcInsnNode ldcInsnNode) {
                appendValue(digest, ldcInsnNode.cst);
            } else if (instruction instanceof IincInsnNode iincInsnNode) {
                append(digest, iincInsnNode.var);
                append(digest, iincInsnNode.incr);
            } else if (instruction instanceof TableSwitchInsnNode tableSwitchInsnNode) {
                append(digest, tableSwitchInsnNode.min);
                append(digest, tableSwitchInsnNode.max);
                append(digest, labelIndex(labels, tableSwitchInsnNode.dflt));
                appendIterable(digest, tableSwitchInsnNode.labels, label -> append(digest, labelIndex(labels, label)));
            } else if (instruction instanceof LookupSwitchInsnNode lookupSwitchInsnNode) {
                append(digest, labelIndex(labels, lookupSwitchInsnNode.dflt));
                appendIterable(digest, lookupSwitchInsnNode.keys, value -> append(digest, value));
                appendIterable(digest, lookupSwitchInsnNode.labels, label -> append(digest, labelIndex(labels, label)));
            } else if (instruction instanceof MultiANewArrayInsnNode multiANewArrayInsnNode) {
                append(digest, multiANewArrayInsnNode.desc);
                append(digest, multiANewArrayInsnNode.dims);
            }
        }
    }

    private static int labelIndex(List<LabelNode> labels, LabelNode labelNode) {
        int index = labels.indexOf(labelNode);
        return index < 0 ? -1 : index;
    }

    private static void appendHandle(MessageDigest digest, Handle handle) {
        append(digest, handle.getTag());
        append(digest, handle.getOwner());
        append(digest, handle.getName());
        append(digest, handle.getDesc());
        append(digest, handle.isInterface());
    }

    private static void appendValue(MessageDigest digest, Object value) {
        if (value == null) {
            append(digest, "<null>");
            return;
        }
        if (value instanceof Handle handle) {
            append(digest, "handle");
            appendHandle(digest, handle);
            return;
        }
        if (value instanceof Type type) {
            append(digest, "type");
            append(digest, type.getDescriptor());
            return;
        }
        if (value.getClass().isArray()) {
            append(digest, "array");
            int length = java.lang.reflect.Array.getLength(value);
            for (int i = 0; i < length; i++) {
                Object element = java.lang.reflect.Array.get(value, i);
                appendValue(digest, element);
            }
            return;
        }
        append(digest, value.getClass().getName());
        append(digest, value.toString());
    }

    private static <T> void appendIterable(MessageDigest digest, Iterable<T> values) {
        if (values == null) {
            append(digest, "<null-iterable>");
            return;
        }
        for (T value : values) {
            appendValue(digest, value);
        }
    }

    private static <T> void appendIterable(MessageDigest digest, Iterable<T> values, Consumer<T> consumer) {
        if (values == null) {
            append(digest, "<null-iterable>");
            return;
        }
        for (T value : values) {
            consumer.accept(value);
        }
    }

    private static void append(MessageDigest digest, String value) {
        if (value == null) {
            digest.update((byte) 0);
            return;
        }
        digest.update((byte) 1);
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }

    private static void append(MessageDigest digest, int value) {
        append(digest, Integer.toString(value));
    }

    private static void append(MessageDigest digest, boolean value) {
        append(digest, value ? "1" : "0");
    }

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
