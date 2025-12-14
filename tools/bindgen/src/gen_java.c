/**
 * @file gen_java.c
 * @brief QUAC Binding Generator - Java Generator
 *
 * Generates Java bindings using JNI (Java Native Interface).
 * Produces:
 * - QUAC100.java: Main Java class with native methods
 * - QUAC100JNI.c: JNI native implementation
 * - Exception classes
 * - Type enumerations
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parser.h"
#include "types.h"
#include "generator.h"

/*=============================================================================
 * Java-Specific Helpers
 *=============================================================================*/

static void java_class_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    char stripped[128];
    gen_strip_suffix(name, "_t", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void java_method_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    gen_to_camel_case(name, out, size);
}

static void java_const_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "QUAC_");
    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
}

static const char *java_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "String";
        if (type->kind == TYPE_UINT8)
            return "byte[]";
        return "long"; /* Handle as pointer */
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "void";
    case TYPE_BOOL:
        return "boolean";
    case TYPE_CHAR:
        return "byte";
    case TYPE_INT8:
        return "byte";
    case TYPE_UINT8:
        return "byte";
    case TYPE_INT16:
        return "short";
    case TYPE_UINT16:
        return "short";
    case TYPE_INT32:
        return "int";
    case TYPE_UINT32:
        return "int";
    case TYPE_INT64:
        return "long";
    case TYPE_UINT64:
        return "long";
    case TYPE_SIZE:
        return "long";
    case TYPE_FLOAT:
        return "float";
    case TYPE_DOUBLE:
        return "double";
    default:
        return "Object";
    }
}

static const char *jni_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "jstring";
        if (type->kind == TYPE_UINT8)
            return "jbyteArray";
        return "jlong";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "void";
    case TYPE_BOOL:
        return "jboolean";
    case TYPE_CHAR:
        return "jbyte";
    case TYPE_INT8:
        return "jbyte";
    case TYPE_UINT8:
        return "jbyte";
    case TYPE_INT16:
        return "jshort";
    case TYPE_UINT16:
        return "jshort";
    case TYPE_INT32:
        return "jint";
    case TYPE_UINT32:
        return "jint";
    case TYPE_INT64:
        return "jlong";
    case TYPE_UINT64:
        return "jlong";
    case TYPE_SIZE:
        return "jlong";
    case TYPE_FLOAT:
        return "jfloat";
    case TYPE_DOUBLE:
        return "jdouble";
    default:
        return "jobject";
    }
}

/*=============================================================================
 * Java Code Generation
 *=============================================================================*/

static void generate_java_header(gen_output_t *out, const char *pkg)
{
    gen_writeln(out, "package %s;", pkg);
    gen_newline(out);
    gen_writeln(out, "import java.nio.ByteBuffer;");
    gen_writeln(out, "import java.util.concurrent.CompletableFuture;");
    gen_newline(out);
}

static void generate_java_exception(gen_output_t *out, const char *pkg)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * Exception thrown by QUAC SDK operations");
    gen_writeln(out, " */");
    gen_writeln(out, "public class QUACException extends Exception {");
    gen_indent(out);
    gen_writeln(out, "private static final long serialVersionUID = 1L;");
    gen_writeln(out, "private final int errorCode;");
    gen_newline(out);
    gen_writeln(out, "public QUACException(int errorCode) {");
    gen_indent(out);
    gen_writeln(out, "super(\"QUAC error: \" + errorCode);");
    gen_writeln(out, "this.errorCode = errorCode;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
    gen_writeln(out, "public QUACException(int errorCode, String message) {");
    gen_indent(out);
    gen_writeln(out, "super(message);");
    gen_writeln(out, "this.errorCode = errorCode;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
    gen_writeln(out, "public int getErrorCode() {");
    gen_indent(out);
    gen_writeln(out, "return errorCode;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
}

static void generate_java_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char class_name[128];
    java_class_name(e->name, class_name, sizeof(class_name));

    gen_writeln(out, "/**");
    if (e->doc[0])
    {
        gen_writeln(out, " * %s", e->doc);
    }
    else
    {
        gen_writeln(out, " * %s enumeration", class_name);
    }
    gen_writeln(out, " */");
    gen_writeln(out, "public enum %s {", class_name);
    gen_indent(out);

    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];
        java_const_name(v->name, value_name, sizeof(value_name));

        if (v->doc[0])
        {
            gen_writeln(out, "/** %s */", v->doc);
        }

        if (i < e->value_count - 1)
        {
            gen_writeln(out, "%s(%lld),", value_name, (long long)v->value);
        }
        else
        {
            gen_writeln(out, "%s(%lld);", value_name, (long long)v->value);
        }
    }
    gen_newline(out);

    gen_writeln(out, "private final int value;");
    gen_newline(out);

    gen_writeln(out, "%s(int value) {", class_name);
    gen_indent(out);
    gen_writeln(out, "this.value = value;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "public int getValue() {");
    gen_indent(out);
    gen_writeln(out, "return value;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "public static %s fromValue(int value) {", class_name);
    gen_indent(out);
    gen_writeln(out, "for (%s e : values()) {", class_name);
    gen_indent(out);
    gen_writeln(out, "if (e.value == value) return e;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "throw new IllegalArgumentException(\"Unknown %s value: \" + value);", class_name);
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
}

static void generate_java_keypair_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * Represents a cryptographic key pair");
    gen_writeln(out, " */");
    gen_writeln(out, "public static class KeyPair {");
    gen_indent(out);
    gen_writeln(out, "private final byte[] publicKey;");
    gen_writeln(out, "private final byte[] secretKey;");
    gen_newline(out);
    gen_writeln(out, "public KeyPair(byte[] publicKey, byte[] secretKey) {");
    gen_indent(out);
    gen_writeln(out, "this.publicKey = publicKey;");
    gen_writeln(out, "this.secretKey = secretKey;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
    gen_writeln(out, "public byte[] getPublicKey() { return publicKey; }");
    gen_writeln(out, "public byte[] getSecretKey() { return secretKey; }");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_java_encaps_result_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * Result of KEM encapsulation");
    gen_writeln(out, " */");
    gen_writeln(out, "public static class EncapsResult {");
    gen_indent(out);
    gen_writeln(out, "private final byte[] ciphertext;");
    gen_writeln(out, "private final byte[] sharedSecret;");
    gen_newline(out);
    gen_writeln(out, "public EncapsResult(byte[] ciphertext, byte[] sharedSecret) {");
    gen_indent(out);
    gen_writeln(out, "this.ciphertext = ciphertext;");
    gen_writeln(out, "this.sharedSecret = sharedSecret;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
    gen_writeln(out, "public byte[] getCiphertext() { return ciphertext; }");
    gen_writeln(out, "public byte[] getSharedSecret() { return sharedSecret; }");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_java_context_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC SDK Context");
    gen_writeln(out, " */");
    gen_writeln(out, "public static class Context implements AutoCloseable {");
    gen_indent(out);
    gen_writeln(out, "private long handle;");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Create a new QUAC context");
    gen_writeln(out, " */");
    gen_writeln(out, "public Context() throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "this.handle = nativeInit();");
    gen_writeln(out, "if (this.handle == 0) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACException(-1, \"Failed to initialize QUAC context\");");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "@Override");
    gen_writeln(out, "public void close() {");
    gen_indent(out);
    gen_writeln(out, "if (handle != 0) {");
    gen_indent(out);
    gen_writeln(out, "nativeShutdown(handle);");
    gen_writeln(out, "handle = 0;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Get number of available devices");
    gen_writeln(out, " */");
    gen_writeln(out, "public int getDeviceCount() throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeGetDeviceCount(handle);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/**");
    gen_writeln(out, " * Open a device by index");
    gen_writeln(out, " */");
    gen_writeln(out, "public Device openDevice(int index) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return new Device(nativeOpenDevice(handle, index));");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "private void checkHandle() throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "if (handle == 0) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACException(-6, \"Context has been closed\");");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_java_device_class(gen_output_t *out)
{
    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC Hardware Device");
    gen_writeln(out, " */");
    gen_writeln(out, "public static class Device implements AutoCloseable {");
    gen_indent(out);
    gen_writeln(out, "private long handle;");
    gen_newline(out);

    gen_writeln(out, "Device(long handle) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "if (handle == 0) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACException(-2, \"Failed to open device\");");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "this.handle = handle;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "@Override");
    gen_writeln(out, "public void close() {");
    gen_indent(out);
    gen_writeln(out, "if (handle != 0) {");
    gen_indent(out);
    gen_writeln(out, "nativeCloseDevice(handle);");
    gen_writeln(out, "handle = 0;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Keygen */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate a KEM keypair");
    gen_writeln(out, " */");
    gen_writeln(out, "public KeyPair kemKeygen(KemAlgorithm algorithm) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeKemKeygen(handle, algorithm.getValue());");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Encaps */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Perform KEM encapsulation");
    gen_writeln(out, " */");
    gen_writeln(out, "public EncapsResult kemEncaps(KemAlgorithm algorithm, byte[] publicKey) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeKemEncaps(handle, algorithm.getValue(), publicKey);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Decaps */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Perform KEM decapsulation");
    gen_writeln(out, " */");
    gen_writeln(out, "public byte[] kemDecaps(KemAlgorithm algorithm, byte[] ciphertext, byte[] secretKey) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeKemDecaps(handle, algorithm.getValue(), ciphertext, secretKey);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Sign Keygen */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate a signature keypair");
    gen_writeln(out, " */");
    gen_writeln(out, "public KeyPair signKeygen(SignAlgorithm algorithm) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeSignKeygen(handle, algorithm.getValue());");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Sign */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Create a signature");
    gen_writeln(out, " */");
    gen_writeln(out, "public byte[] sign(SignAlgorithm algorithm, byte[] message, byte[] secretKey) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeSign(handle, algorithm.getValue(), message, secretKey);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Verify */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Verify a signature");
    gen_writeln(out, " */");
    gen_writeln(out, "public boolean verify(SignAlgorithm algorithm, byte[] message, byte[] signature, byte[] publicKey) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeVerify(handle, algorithm.getValue(), message, signature, publicKey);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Random */
    gen_writeln(out, "/**");
    gen_writeln(out, " * Generate random bytes");
    gen_writeln(out, " */");
    gen_writeln(out, "public byte[] random(int length) throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "checkHandle();");
    gen_writeln(out, "return nativeRandom(handle, length);");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "private void checkHandle() throws QUACException {");
    gen_indent(out);
    gen_writeln(out, "if (handle == 0) {");
    gen_indent(out);
    gen_writeln(out, "throw new QUACException(-6, \"Device has been closed\");");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_java_native_methods(gen_output_t *out)
{
    gen_writeln(out, "// Native method declarations");
    gen_writeln(out, "private static native long nativeInit();");
    gen_writeln(out, "private static native void nativeShutdown(long handle);");
    gen_writeln(out, "private static native int nativeGetDeviceCount(long handle);");
    gen_writeln(out, "private static native long nativeOpenDevice(long ctxHandle, int index);");
    gen_writeln(out, "private static native void nativeCloseDevice(long handle);");
    gen_writeln(out, "private static native KeyPair nativeKemKeygen(long handle, int algorithm);");
    gen_writeln(out, "private static native EncapsResult nativeKemEncaps(long handle, int algorithm, byte[] publicKey);");
    gen_writeln(out, "private static native byte[] nativeKemDecaps(long handle, int algorithm, byte[] ciphertext, byte[] secretKey);");
    gen_writeln(out, "private static native KeyPair nativeSignKeygen(long handle, int algorithm);");
    gen_writeln(out, "private static native byte[] nativeSign(long handle, int algorithm, byte[] message, byte[] secretKey);");
    gen_writeln(out, "private static native boolean nativeVerify(long handle, int algorithm, byte[] message, byte[] signature, byte[] publicKey);");
    gen_writeln(out, "private static native byte[] nativeRandom(long handle, int length);");
    gen_newline(out);

    gen_writeln(out, "static {");
    gen_indent(out);
    gen_writeln(out, "System.loadLibrary(\"quac100_jni\");");
    gen_dedent(out);
    gen_writeln(out, "}");
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_java(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    const char *pkg = "com.dyber.quac100";

    /* Create directory structure */
    char dir_path[1024];
    snprintf(dir_path, sizeof(dir_path), "%s/com/dyber/quac100", config->output_dir);

    char path[1024];

    /* Generate exception class */
    snprintf(path, sizeof(path), "%s/QUACException.java", dir_path);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    if (config->dry_run)
    {
        return 0;
    }

    gen_output_t *out = gen_output_create_file(path);
    if (!out)
    {
        fprintf(stderr, "Error: Cannot create %s\n", path);
        return -1;
    }

    gen_write_file_header(out, "QUACException.java",
                          "QUAC SDK Exception class", TARGET_JAVA);
    generate_java_header(out, pkg);
    generate_java_exception(out, pkg);
    gen_output_destroy(out);

    /* Generate enum files */
    for (int i = 0; i < api->enum_count; i++)
    {
        const parsed_enum_t *e = &api->enums[i];
        char class_name[128];
        java_class_name(e->name, class_name, sizeof(class_name));

        snprintf(path, sizeof(path), "%s/%s.java", dir_path, class_name);

        if (config->verbose)
        {
            printf("  Generating: %s\n", path);
        }

        out = gen_output_create_file(path);
        if (out)
        {
            char desc[256];
            snprintf(desc, sizeof(desc), "%s enumeration", class_name);
            gen_write_file_header(out, path, desc, TARGET_JAVA);
            generate_java_header(out, pkg);
            generate_java_enum(out, e);
            gen_output_destroy(out);
        }
    }

    /* Generate main QUAC100 class */
    snprintf(path, sizeof(path), "%s/QUAC100.java", dir_path);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (!out)
    {
        fprintf(stderr, "Error: Cannot create %s\n", path);
        return -1;
    }

    gen_write_file_header(out, "QUAC100.java",
                          "Main QUAC 100 SDK Java bindings", TARGET_JAVA);
    generate_java_header(out, pkg);

    gen_writeln(out, "/**");
    gen_writeln(out, " * QUAC 100 Post-Quantum Cryptographic Accelerator SDK");
    gen_writeln(out, " * <p>");
    gen_writeln(out, " * Example usage:");
    gen_writeln(out, " * <pre>");
    gen_writeln(out, " * try (QUAC100.Context ctx = new QUAC100.Context()) {");
    gen_writeln(out, " *     try (QUAC100.Device device = ctx.openDevice(0)) {");
    gen_writeln(out, " *         QUAC100.KeyPair kp = device.kemKeygen(KemAlgorithm.ML_KEM_768);");
    gen_writeln(out, " *         // Use keys...");
    gen_writeln(out, " *     }");
    gen_writeln(out, " * }");
    gen_writeln(out, " * </pre>");
    gen_writeln(out, " */");
    gen_writeln(out, "public final class QUAC100 {");
    gen_indent(out);

    gen_writeln(out, "private QUAC100() {} // Prevent instantiation");
    gen_newline(out);

    generate_java_keypair_class(out);
    generate_java_encaps_result_class(out);
    generate_java_context_class(out);
    generate_java_device_class(out);
    generate_java_native_methods(out);

    gen_dedent(out);
    gen_writeln(out, "}");

    gen_output_destroy(out);

    return 0;
}