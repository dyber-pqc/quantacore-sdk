/**
 * @file gen_csharp.c
 * @brief QUAC Binding Generator - C# Generator
 *
 * Generates C# bindings using P/Invoke for native interop.
 * Produces:
 * - QUAC100.cs: Main C# class with P/Invoke declarations
 * - Enum files
 * - Struct files
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
 * C#-Specific Helpers
 *=============================================================================*/

static void csharp_class_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    char stripped[128];
    gen_strip_suffix(name, "_t", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void csharp_method_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    gen_to_pascal_case(name, out, size);
}

static void csharp_const_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "QUAC_");
    gen_to_pascal_case(name, out, size);
}

static const char *csharp_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "string";
        if (type->kind == TYPE_UINT8)
            return "byte[]";
        if (type->kind == TYPE_VOID)
            return "IntPtr";
        return "IntPtr";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "void";
    case TYPE_BOOL:
        return "bool";
    case TYPE_CHAR:
        return "byte";
    case TYPE_INT8:
        return "sbyte";
    case TYPE_UINT8:
        return "byte";
    case TYPE_INT16:
        return "short";
    case TYPE_UINT16:
        return "ushort";
    case TYPE_INT32:
        return "int";
    case TYPE_UINT32:
        return "uint";
    case TYPE_INT64:
        return "long";
    case TYPE_UINT64:
        return "ulong";
    case TYPE_SIZE:
        return "UIntPtr";
    case TYPE_FLOAT:
        return "float";
    case TYPE_DOUBLE:
        return "double";
    default:
        return "object";
    }
}

static const char *csharp_marshal_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
        {
            return "[MarshalAs(UnmanagedType.LPStr)]";
        }
        if (type->kind == TYPE_UINT8)
        {
            return "[MarshalAs(UnmanagedType.LPArray)]";
        }
    }

    switch (type->kind)
    {
    case TYPE_BOOL:
        return "[MarshalAs(UnmanagedType.I1)]";
    default:
        return "";
    }
}

/*=============================================================================
 * C# Code Generation
 *=============================================================================*/

static void generate_csharp_header(gen_output_t *out, const char *ns)
{
    gen_writeln(out, "using System;");
    gen_writeln(out, "using System.Runtime.InteropServices;");
    gen_writeln(out, "using System.Threading.Tasks;");
    gen_newline(out);
    gen_writeln(out, "namespace %s", ns);
    gen_writeln(out, "{");
}

static void generate_csharp_footer(gen_output_t *out)
{
    gen_writeln(out, "}");
}

static void generate_csharp_exception(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// Exception thrown by QUAC SDK operations");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public class QUACException : Exception");
    gen_writeln(out, "    {");
    gen_indent(out);
    gen_writeln(out, "        public int ErrorCode { get; }");
    gen_newline(out);
    gen_writeln(out, "        public QUACException(int errorCode)");
    gen_writeln(out, "            : base($\"QUAC error: {errorCode}\")");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ErrorCode = errorCode;");
    gen_writeln(out, "        }");
    gen_newline(out);
    gen_writeln(out, "        public QUACException(int errorCode, string message)");
    gen_writeln(out, "            : base(message)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ErrorCode = errorCode;");
    gen_writeln(out, "        }");
    gen_dedent(out);
    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char class_name[128];
    csharp_class_name(e->name, class_name, sizeof(class_name));

    gen_writeln(out, "    /// <summary>");
    if (e->doc[0])
    {
        gen_writeln(out, "    /// %s", e->doc);
    }
    else
    {
        gen_writeln(out, "    /// %s enumeration", class_name);
    }
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public enum %s", class_name);
    gen_writeln(out, "    {");

    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];
        csharp_const_name(v->name, value_name, sizeof(value_name));

        if (v->doc[0])
        {
            gen_writeln(out, "        /// <summary>%s</summary>", v->doc);
        }
        gen_writeln(out, "        %s = %lld,", value_name, (long long)v->value);
    }

    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_keypair_struct(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// Represents a cryptographic key pair");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public readonly struct KeyPair");
    gen_writeln(out, "    {");
    gen_writeln(out, "        public byte[] PublicKey { get; }");
    gen_writeln(out, "        public byte[] SecretKey { get; }");
    gen_newline(out);
    gen_writeln(out, "        public KeyPair(byte[] publicKey, byte[] secretKey)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            PublicKey = publicKey;");
    gen_writeln(out, "            SecretKey = secretKey;");
    gen_writeln(out, "        }");
    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_encaps_result_struct(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// Result of KEM encapsulation");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public readonly struct EncapsResult");
    gen_writeln(out, "    {");
    gen_writeln(out, "        public byte[] Ciphertext { get; }");
    gen_writeln(out, "        public byte[] SharedSecret { get; }");
    gen_newline(out);
    gen_writeln(out, "        public EncapsResult(byte[] ciphertext, byte[] sharedSecret)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            Ciphertext = ciphertext;");
    gen_writeln(out, "            SharedSecret = sharedSecret;");
    gen_writeln(out, "        }");
    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_native_methods(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// Native P/Invoke declarations");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    internal static class NativeMethods");
    gen_writeln(out, "    {");
    gen_writeln(out, "        private const string LibraryName = \"quac100\";");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_init(out IntPtr ctx);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_shutdown(IntPtr ctx);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_get_device_count(IntPtr ctx, out uint count);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_open_device(IntPtr ctx, uint index, out IntPtr device);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_close_device(IntPtr device);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_kem_keygen(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] publicKey,");
    gen_writeln(out, "            ref UIntPtr publicKeyLen,");
    gen_writeln(out, "            byte[] secretKey,");
    gen_writeln(out, "            ref UIntPtr secretKeyLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_kem_encaps(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] publicKey,");
    gen_writeln(out, "            UIntPtr publicKeyLen,");
    gen_writeln(out, "            byte[] ciphertext,");
    gen_writeln(out, "            ref UIntPtr ciphertextLen,");
    gen_writeln(out, "            byte[] sharedSecret,");
    gen_writeln(out, "            ref UIntPtr sharedSecretLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_kem_decaps(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] ciphertext,");
    gen_writeln(out, "            UIntPtr ciphertextLen,");
    gen_writeln(out, "            byte[] secretKey,");
    gen_writeln(out, "            UIntPtr secretKeyLen,");
    gen_writeln(out, "            byte[] sharedSecret,");
    gen_writeln(out, "            ref UIntPtr sharedSecretLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_sign_keygen(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] publicKey,");
    gen_writeln(out, "            ref UIntPtr publicKeyLen,");
    gen_writeln(out, "            byte[] secretKey,");
    gen_writeln(out, "            ref UIntPtr secretKeyLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_sign(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] message,");
    gen_writeln(out, "            UIntPtr messageLen,");
    gen_writeln(out, "            byte[] secretKey,");
    gen_writeln(out, "            UIntPtr secretKeyLen,");
    gen_writeln(out, "            byte[] signature,");
    gen_writeln(out, "            ref UIntPtr signatureLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_verify(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            int algorithm,");
    gen_writeln(out, "            byte[] message,");
    gen_writeln(out, "            UIntPtr messageLen,");
    gen_writeln(out, "            byte[] signature,");
    gen_writeln(out, "            UIntPtr signatureLen,");
    gen_writeln(out, "            byte[] publicKey,");
    gen_writeln(out, "            UIntPtr publicKeyLen);");
    gen_newline(out);
    gen_writeln(out, "        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]");
    gen_writeln(out, "        public static extern int quac_random(");
    gen_writeln(out, "            IntPtr device,");
    gen_writeln(out, "            byte[] buffer,");
    gen_writeln(out, "            UIntPtr length);");
    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_context_class(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// QUAC SDK Context");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public sealed class Context : IDisposable");
    gen_writeln(out, "    {");
    gen_writeln(out, "        private IntPtr _handle;");
    gen_writeln(out, "        private bool _disposed;");
    gen_newline(out);

    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Create a new QUAC context");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public Context()");
    gen_writeln(out, "        {");
    gen_writeln(out, "            int result = NativeMethods.quac_init(out _handle);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result, \"Failed to initialize QUAC context\");");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Get the number of available devices");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public uint DeviceCount");
    gen_writeln(out, "        {");
    gen_writeln(out, "            get");
    gen_writeln(out, "            {");
    gen_writeln(out, "                ThrowIfDisposed();");
    gen_writeln(out, "                int result = NativeMethods.quac_get_device_count(_handle, out uint count);");
    gen_writeln(out, "                if (result != 0)");
    gen_writeln(out, "                    throw new QUACException(result);");
    gen_writeln(out, "                return count;");
    gen_writeln(out, "            }");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Open a device by index");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public Device OpenDevice(uint index)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ThrowIfDisposed();");
    gen_writeln(out, "            int result = NativeMethods.quac_open_device(_handle, index, out IntPtr deviceHandle);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result, $\"Failed to open device {index}\");");
    gen_writeln(out, "            return new Device(deviceHandle);");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        public void Dispose()");
    gen_writeln(out, "        {");
    gen_writeln(out, "            if (!_disposed)");
    gen_writeln(out, "            {");
    gen_writeln(out, "                if (_handle != IntPtr.Zero)");
    gen_writeln(out, "                {");
    gen_writeln(out, "                    NativeMethods.quac_shutdown(_handle);");
    gen_writeln(out, "                    _handle = IntPtr.Zero;");
    gen_writeln(out, "                }");
    gen_writeln(out, "                _disposed = true;");
    gen_writeln(out, "            }");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        private void ThrowIfDisposed()");
    gen_writeln(out, "        {");
    gen_writeln(out, "            if (_disposed)");
    gen_writeln(out, "                throw new ObjectDisposedException(nameof(Context));");
    gen_writeln(out, "        }");
    gen_writeln(out, "    }");
    gen_newline(out);
}

static void generate_csharp_device_class(gen_output_t *out)
{
    gen_writeln(out, "    /// <summary>");
    gen_writeln(out, "    /// QUAC Hardware Device");
    gen_writeln(out, "    /// </summary>");
    gen_writeln(out, "    public sealed class Device : IDisposable");
    gen_writeln(out, "    {");
    gen_writeln(out, "        private IntPtr _handle;");
    gen_writeln(out, "        private bool _disposed;");
    gen_newline(out);

    gen_writeln(out, "        internal Device(IntPtr handle)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            _handle = handle;");
    gen_writeln(out, "        }");
    gen_newline(out);

    /* KEM Keygen */
    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Generate a KEM keypair");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public KeyPair KemKeygen(KemAlgorithm algorithm)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ThrowIfDisposed();");
    gen_writeln(out, "            byte[] pk = new byte[2048];");
    gen_writeln(out, "            byte[] sk = new byte[4096];");
    gen_writeln(out, "            UIntPtr pkLen = (UIntPtr)pk.Length;");
    gen_writeln(out, "            UIntPtr skLen = (UIntPtr)sk.Length;");
    gen_newline(out);
    gen_writeln(out, "            int result = NativeMethods.quac_kem_keygen(");
    gen_writeln(out, "                _handle, (int)algorithm, pk, ref pkLen, sk, ref skLen);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result);");
    gen_newline(out);
    gen_writeln(out, "            Array.Resize(ref pk, (int)pkLen);");
    gen_writeln(out, "            Array.Resize(ref sk, (int)skLen);");
    gen_writeln(out, "            return new KeyPair(pk, sk);");
    gen_writeln(out, "        }");
    gen_newline(out);

    /* KEM Encaps */
    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Perform KEM encapsulation");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public EncapsResult KemEncaps(KemAlgorithm algorithm, byte[] publicKey)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ThrowIfDisposed();");
    gen_writeln(out, "            byte[] ct = new byte[2048];");
    gen_writeln(out, "            byte[] ss = new byte[64];");
    gen_writeln(out, "            UIntPtr ctLen = (UIntPtr)ct.Length;");
    gen_writeln(out, "            UIntPtr ssLen = (UIntPtr)ss.Length;");
    gen_newline(out);
    gen_writeln(out, "            int result = NativeMethods.quac_kem_encaps(");
    gen_writeln(out, "                _handle, (int)algorithm,");
    gen_writeln(out, "                publicKey, (UIntPtr)publicKey.Length,");
    gen_writeln(out, "                ct, ref ctLen, ss, ref ssLen);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result);");
    gen_newline(out);
    gen_writeln(out, "            Array.Resize(ref ct, (int)ctLen);");
    gen_writeln(out, "            Array.Resize(ref ss, (int)ssLen);");
    gen_writeln(out, "            return new EncapsResult(ct, ss);");
    gen_writeln(out, "        }");
    gen_newline(out);

    /* KEM Decaps */
    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Perform KEM decapsulation");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public byte[] KemDecaps(KemAlgorithm algorithm, byte[] ciphertext, byte[] secretKey)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ThrowIfDisposed();");
    gen_writeln(out, "            byte[] ss = new byte[64];");
    gen_writeln(out, "            UIntPtr ssLen = (UIntPtr)ss.Length;");
    gen_newline(out);
    gen_writeln(out, "            int result = NativeMethods.quac_kem_decaps(");
    gen_writeln(out, "                _handle, (int)algorithm,");
    gen_writeln(out, "                ciphertext, (UIntPtr)ciphertext.Length,");
    gen_writeln(out, "                secretKey, (UIntPtr)secretKey.Length,");
    gen_writeln(out, "                ss, ref ssLen);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result);");
    gen_newline(out);
    gen_writeln(out, "            Array.Resize(ref ss, (int)ssLen);");
    gen_writeln(out, "            return ss;");
    gen_writeln(out, "        }");
    gen_newline(out);

    /* Random */
    gen_writeln(out, "        /// <summary>");
    gen_writeln(out, "        /// Generate random bytes using QRNG");
    gen_writeln(out, "        /// </summary>");
    gen_writeln(out, "        public byte[] Random(int length)");
    gen_writeln(out, "        {");
    gen_writeln(out, "            ThrowIfDisposed();");
    gen_writeln(out, "            if (length <= 0)");
    gen_writeln(out, "                throw new ArgumentOutOfRangeException(nameof(length));");
    gen_newline(out);
    gen_writeln(out, "            byte[] buffer = new byte[length];");
    gen_writeln(out, "            int result = NativeMethods.quac_random(_handle, buffer, (UIntPtr)length);");
    gen_writeln(out, "            if (result != 0)");
    gen_writeln(out, "                throw new QUACException(result);");
    gen_writeln(out, "            return buffer;");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        public void Dispose()");
    gen_writeln(out, "        {");
    gen_writeln(out, "            if (!_disposed)");
    gen_writeln(out, "            {");
    gen_writeln(out, "                if (_handle != IntPtr.Zero)");
    gen_writeln(out, "                {");
    gen_writeln(out, "                    NativeMethods.quac_close_device(_handle);");
    gen_writeln(out, "                    _handle = IntPtr.Zero;");
    gen_writeln(out, "                }");
    gen_writeln(out, "                _disposed = true;");
    gen_writeln(out, "            }");
    gen_writeln(out, "        }");
    gen_newline(out);

    gen_writeln(out, "        private void ThrowIfDisposed()");
    gen_writeln(out, "        {");
    gen_writeln(out, "            if (_disposed)");
    gen_writeln(out, "                throw new ObjectDisposedException(nameof(Device));");
    gen_writeln(out, "        }");
    gen_writeln(out, "    }");
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_csharp(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    const char *ns = "Dyber.QUAC100";

    char path[1024];
    snprintf(path, sizeof(path), "%s/QUAC100.cs", config->output_dir);

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

    gen_write_file_header(out, "QUAC100.cs",
                          "C# bindings for QUAC 100 SDK", TARGET_CSHARP);

    generate_csharp_header(out, ns);
    generate_csharp_exception(out);

    /* Enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        generate_csharp_enum(out, &api->enums[i]);
    }

    generate_csharp_keypair_struct(out);
    generate_csharp_encaps_result_struct(out);
    generate_csharp_native_methods(out);
    generate_csharp_context_class(out);
    generate_csharp_device_class(out);

    generate_csharp_footer(out);

    gen_output_destroy(out);

    /* Generate .csproj file */
    snprintf(path, sizeof(path), "%s/QUAC100.csproj", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        gen_writeln(out, "<Project Sdk=\"Microsoft.NET.Sdk\">");
        gen_writeln(out, "  <PropertyGroup>");
        gen_writeln(out, "    <TargetFramework>net8.0</TargetFramework>");
        gen_writeln(out, "    <ImplicitUsings>enable</ImplicitUsings>");
        gen_writeln(out, "    <Nullable>enable</Nullable>");
        gen_writeln(out, "    <PackageId>Dyber.QUAC100</PackageId>");
        gen_writeln(out, "    <Version>1.0.0</Version>");
        gen_writeln(out, "    <Authors>Dyber, Inc.</Authors>");
        gen_writeln(out, "    <Company>Dyber, Inc.</Company>");
        gen_writeln(out, "    <Description>C# bindings for QUAC 100 post-quantum cryptographic accelerator</Description>");
        gen_writeln(out, "  </PropertyGroup>");
        gen_writeln(out, "</Project>");
        gen_output_destroy(out);
    }

    return 0;
}