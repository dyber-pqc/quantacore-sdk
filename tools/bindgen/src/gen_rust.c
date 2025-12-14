/**
 * @file gen_rust.c
 * @brief QUAC Binding Generator - Rust Generator
 *
 * Generates Rust bindings with safe wrappers around unsafe FFI.
 * Produces:
 * - lib.rs: Safe Rust API with Result types
 * - ffi.rs: Raw FFI bindings
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
 * Rust-Specific Helpers
 *=============================================================================*/

static void rust_type_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    char stripped[128];
    gen_strip_suffix(name, "_t", stripped, sizeof(stripped));
    gen_to_pascal_case(stripped, out, size);
}

static void rust_func_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "quac_");
    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
}

static void rust_const_name(const char *c_name, char *out, size_t size)
{
    const char *name = gen_strip_prefix(c_name, "QUAC_");
    strncpy(out, name, size - 1);
    out[size - 1] = '\0';
}

static const char *rust_ffi_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->qualifiers & QUAL_CONST)
        {
            if (type->kind == TYPE_CHAR)
                return "*const c_char";
            if (type->kind == TYPE_VOID)
                return "*const c_void";
            return "*const c_void";
        }
        else
        {
            if (type->kind == TYPE_CHAR)
                return "*mut c_char";
            if (type->kind == TYPE_VOID)
                return "*mut c_void";
            return "*mut c_void";
        }
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "()";
    case TYPE_BOOL:
        return "bool";
    case TYPE_CHAR:
        return "c_char";
    case TYPE_INT8:
        return "i8";
    case TYPE_UINT8:
        return "u8";
    case TYPE_INT16:
        return "i16";
    case TYPE_UINT16:
        return "u16";
    case TYPE_INT32:
        return "i32";
    case TYPE_UINT32:
        return "u32";
    case TYPE_INT64:
        return "i64";
    case TYPE_UINT64:
        return "u64";
    case TYPE_SIZE:
        return "usize";
    case TYPE_FLOAT:
        return "f32";
    case TYPE_DOUBLE:
        return "f64";
    default:
        return "c_void";
    }
}

static const char *rust_safe_type(const parsed_type_t *type)
{
    if (type->pointer_depth > 0)
    {
        if (type->kind == TYPE_CHAR)
            return "&str";
        if (type->kind == TYPE_UINT8)
            return "&[u8]";
        return "*mut c_void";
    }

    switch (type->kind)
    {
    case TYPE_VOID:
        return "()";
    case TYPE_BOOL:
        return "bool";
    case TYPE_CHAR:
        return "i8";
    case TYPE_INT8:
        return "i8";
    case TYPE_UINT8:
        return "u8";
    case TYPE_INT16:
        return "i16";
    case TYPE_UINT16:
        return "u16";
    case TYPE_INT32:
        return "i32";
    case TYPE_UINT32:
        return "u32";
    case TYPE_INT64:
        return "i64";
    case TYPE_UINT64:
        return "u64";
    case TYPE_SIZE:
        return "usize";
    case TYPE_FLOAT:
        return "f32";
    case TYPE_DOUBLE:
        return "f64";
    default:
        return "()";
    }
}

/*=============================================================================
 * FFI Module Generation
 *=============================================================================*/

static void generate_ffi_imports(gen_output_t *out)
{
    gen_writeln(out, "use std::os::raw::{c_char, c_void, c_int};");
    gen_newline(out);
}

static void generate_ffi_type_aliases(gen_output_t *out)
{
    gen_writeln(out, "// Type aliases for opaque handles");
    gen_writeln(out, "pub type QuacContext = *mut c_void;");
    gen_writeln(out, "pub type QuacDevice = *mut c_void;");
    gen_writeln(out, "pub type QuacAsyncHandle = *mut c_void;");
    gen_writeln(out, "pub type QuacBatch = *mut c_void;");
    gen_writeln(out, "pub type QuacKeyHandle = u32;");
    gen_writeln(out, "pub type QuacResult = i32;");
    gen_newline(out);
}

static void generate_ffi_enum(gen_output_t *out, const parsed_enum_t *e)
{
    char type_name[128];
    rust_type_name(e->name, type_name, sizeof(type_name));

    if (e->doc[0])
    {
        gen_write_doc_comment(out, e->doc, TARGET_RUST);
    }

    gen_writeln(out, "#[repr(i32)]");
    gen_writeln(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]");
    gen_writeln(out, "pub enum %s {", type_name);
    gen_indent(out);

    for (int i = 0; i < e->value_count; i++)
    {
        const parsed_enum_value_t *v = &e->values[i];
        char value_name[128];

        /* Convert enum value name to PascalCase */
        const char *stripped = gen_strip_prefix(v->name, "QUAC_");
        gen_to_pascal_case(stripped, value_name, sizeof(value_name));

        if (v->doc[0])
        {
            gen_writeln(out, "/// %s", v->doc);
        }
        gen_writeln(out, "%s = %lld,", value_name, (long long)v->value);
    }

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Implement Default if there's a zero value */
    for (int i = 0; i < e->value_count; i++)
    {
        if (e->values[i].value == 0)
        {
            char value_name[128];
            const char *stripped = gen_strip_prefix(e->values[i].name, "QUAC_");
            gen_to_pascal_case(stripped, value_name, sizeof(value_name));

            gen_writeln(out, "impl Default for %s {", type_name);
            gen_indent(out);
            gen_writeln(out, "fn default() -> Self {");
            gen_indent(out);
            gen_writeln(out, "%s::%s", type_name, value_name);
            gen_dedent(out);
            gen_writeln(out, "}");
            gen_dedent(out);
            gen_writeln(out, "}");
            gen_newline(out);
            break;
        }
    }
}

static void generate_ffi_struct(gen_output_t *out, const parsed_struct_t *s)
{
    if (s->is_opaque)
    {
        char type_name[128];
        rust_type_name(s->name, type_name, sizeof(type_name));
        gen_writeln(out, "/// Opaque type: %s", s->name);
        gen_writeln(out, "pub type %s = *mut c_void;", type_name);
        gen_newline(out);
        return;
    }

    char type_name[128];
    rust_type_name(s->name, type_name, sizeof(type_name));

    if (s->doc[0])
    {
        gen_write_doc_comment(out, s->doc, TARGET_RUST);
    }

    gen_writeln(out, "#[repr(C)]");
    gen_writeln(out, "#[derive(Debug, Clone)]");
    gen_writeln(out, "pub struct %s {", type_name);
    gen_indent(out);

    for (int i = 0; i < s->field_count; i++)
    {
        const parsed_field_t *f = &s->fields[i];
        const char *ffi_type = rust_ffi_type(&f->type);

        if (f->doc[0])
        {
            gen_writeln(out, "/// %s", f->doc);
        }

        /* Handle arrays */
        if (f->type.array_size > 0)
        {
            gen_writeln(out, "pub %s: [%s; %d],", f->name, ffi_type, f->type.array_size);
        }
        else
        {
            gen_writeln(out, "pub %s: %s,", f->name, ffi_type);
        }
    }

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Generate Default impl */
    gen_writeln(out, "impl Default for %s {", type_name);
    gen_indent(out);
    gen_writeln(out, "fn default() -> Self {");
    gen_indent(out);
    gen_writeln(out, "unsafe { std::mem::zeroed() }");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_ffi_function(gen_output_t *out, const parsed_function_t *f)
{
    if (f->doc[0])
    {
        /* Indent doc comment for extern block */
        char *doc_copy = strdup(f->doc);
        char *line = strtok(doc_copy, "\n");
        while (line)
        {
            gen_writeln(out, "    /// %s", line);
            line = strtok(NULL, "\n");
        }
        free(doc_copy);
    }

    gen_write(out, "    pub fn %s(", f->name);

    for (int i = 0; i < f->param_count; i++)
    {
        const parsed_param_t *param = &f->params[i];
        const char *ffi_type = rust_ffi_type(&param->type);

        if (i > 0)
            gen_write(out, ", ");
        gen_write(out, "%s: %s", param->name, ffi_type);
    }

    const char *ret_type = rust_ffi_type(&f->return_type);
    if (f->return_type.kind == TYPE_VOID && f->return_type.pointer_depth == 0)
    {
        gen_writeln(out, ");");
    }
    else
    {
        gen_writeln(out, ") -> %s;", ret_type);
    }
}

/*=============================================================================
 * Safe Wrapper Generation
 *=============================================================================*/

static void generate_error_type(gen_output_t *out)
{
    gen_writeln(out, "/// QUAC SDK error type");
    gen_writeln(out, "#[derive(Debug, Clone)]");
    gen_writeln(out, "pub struct Error {");
    gen_indent(out);
    gen_writeln(out, "/// Error code from the SDK");
    gen_writeln(out, "pub code: i32,");
    gen_writeln(out, "/// Human-readable error message");
    gen_writeln(out, "pub message: String,");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "impl std::fmt::Display for Error {");
    gen_indent(out);
    gen_writeln(out, "fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {");
    gen_indent(out);
    gen_writeln(out, "write!(f, \"QUAC error {}: {}\", self.code, self.message)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "impl std::error::Error for Error {}");
    gen_newline(out);

    gen_writeln(out, "/// Result type for QUAC operations");
    gen_writeln(out, "pub type Result<T> = std::result::Result<T, Error>;");
    gen_newline(out);

    gen_writeln(out, "/// Convert a QUAC result code to a Result");
    gen_writeln(out, "fn check_result(code: i32) -> Result<()> {");
    gen_indent(out);
    gen_writeln(out, "if code == 0 {");
    gen_indent(out);
    gen_writeln(out, "Ok(())");
    gen_dedent(out);
    gen_writeln(out, "} else {");
    gen_indent(out);
    gen_writeln(out, "Err(Error {");
    gen_indent(out);
    gen_writeln(out, "code,");
    gen_writeln(out, "message: format!(\"QUAC operation failed with code {}\", code),");
    gen_dedent(out);
    gen_writeln(out, "})");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_context_wrapper(gen_output_t *out)
{
    gen_writeln(out, "/// QUAC Context - Main SDK entry point");
    gen_writeln(out, "///");
    gen_writeln(out, "/// The Context manages the lifecycle of the QUAC SDK and provides");
    gen_writeln(out, "/// access to available cryptographic devices.");
    gen_writeln(out, "pub struct Context {");
    gen_indent(out);
    gen_writeln(out, "handle: ffi::QuacContext,");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "// Context is Send + Sync as the underlying handle is thread-safe");
    gen_writeln(out, "unsafe impl Send for Context {}");
    gen_writeln(out, "unsafe impl Sync for Context {}");
    gen_newline(out);

    gen_writeln(out, "impl Context {");
    gen_indent(out);

    gen_writeln(out, "/// Create a new QUAC context");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Example");
    gen_writeln(out, "/// ```");
    gen_writeln(out, "/// let ctx = quac100::Context::new()?;");
    gen_writeln(out, "/// ```");
    gen_writeln(out, "pub fn new() -> Result<Self> {");
    gen_indent(out);
    gen_writeln(out, "let mut handle: ffi::QuacContext = std::ptr::null_mut();");
    gen_writeln(out, "let result = unsafe { ffi::quac_init(&mut handle) };");
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "Ok(Self { handle })");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/// Get the number of available devices");
    gen_writeln(out, "pub fn device_count(&self) -> Result<u32> {");
    gen_indent(out);
    gen_writeln(out, "let mut count: u32 = 0;");
    gen_writeln(out, "let result = unsafe { ffi::quac_get_device_count(self.handle, &mut count) };");
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "Ok(count)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/// Open a device by index");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Arguments");
    gen_writeln(out, "/// * `index` - Zero-based device index");
    gen_writeln(out, "pub fn open_device(&self, index: u32) -> Result<Device> {");
    gen_indent(out);
    gen_writeln(out, "let mut handle: ffi::QuacDevice = std::ptr::null_mut();");
    gen_writeln(out, "let result = unsafe { ffi::quac_open_device(self.handle, index, &mut handle) };");
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "Ok(Device { handle })");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/// Get the raw handle (for advanced use)");
    gen_writeln(out, "pub fn as_raw(&self) -> ffi::QuacContext {");
    gen_indent(out);
    gen_writeln(out, "self.handle");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "impl Drop for Context {");
    gen_indent(out);
    gen_writeln(out, "fn drop(&mut self) {");
    gen_indent(out);
    gen_writeln(out, "if !self.handle.is_null() {");
    gen_indent(out);
    gen_writeln(out, "unsafe { ffi::quac_shutdown(self.handle); }");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

static void generate_device_wrapper(gen_output_t *out)
{
    gen_writeln(out, "/// QUAC Device - Hardware accelerator interface");
    gen_writeln(out, "///");
    gen_writeln(out, "/// Provides access to cryptographic operations on a specific QUAC device.");
    gen_writeln(out, "pub struct Device {");
    gen_indent(out);
    gen_writeln(out, "handle: ffi::QuacDevice,");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "unsafe impl Send for Device {}");
    gen_writeln(out, "unsafe impl Sync for Device {}");
    gen_newline(out);

    gen_writeln(out, "impl Device {");
    gen_indent(out);

    /* KEM Keygen */
    gen_writeln(out, "/// Generate a KEM keypair");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Arguments");
    gen_writeln(out, "/// * `algorithm` - The KEM algorithm to use");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Returns");
    gen_writeln(out, "/// A tuple of (public_key, secret_key) as byte vectors");
    gen_writeln(out, "pub fn kem_keygen(&self, algorithm: ffi::KemAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {");
    gen_indent(out);
    gen_writeln(out, "let mut pk = vec![0u8; 2048];");
    gen_writeln(out, "let mut sk = vec![0u8; 4096];");
    gen_writeln(out, "let mut pk_len: usize = pk.len();");
    gen_writeln(out, "let mut sk_len: usize = sk.len();");
    gen_newline(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_kem_keygen(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "pk.as_mut_ptr(),");
    gen_writeln(out, "&mut pk_len,");
    gen_writeln(out, "sk.as_mut_ptr(),");
    gen_writeln(out, "&mut sk_len,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "pk.truncate(pk_len);");
    gen_writeln(out, "sk.truncate(sk_len);");
    gen_writeln(out, "Ok((pk, sk))");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Encaps */
    gen_writeln(out, "/// Encapsulate to produce ciphertext and shared secret");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Arguments");
    gen_writeln(out, "/// * `algorithm` - The KEM algorithm");
    gen_writeln(out, "/// * `pk` - The public key");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Returns");
    gen_writeln(out, "/// A tuple of (ciphertext, shared_secret)");
    gen_writeln(out, "pub fn kem_encaps(&self, algorithm: ffi::KemAlgorithm, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {");
    gen_indent(out);
    gen_writeln(out, "let mut ct = vec![0u8; 2048];");
    gen_writeln(out, "let mut ss = vec![0u8; 64];");
    gen_writeln(out, "let mut ct_len: usize = ct.len();");
    gen_writeln(out, "let mut ss_len: usize = ss.len();");
    gen_newline(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_kem_encaps(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "pk.as_ptr(),");
    gen_writeln(out, "pk.len(),");
    gen_writeln(out, "ct.as_mut_ptr(),");
    gen_writeln(out, "&mut ct_len,");
    gen_writeln(out, "ss.as_mut_ptr(),");
    gen_writeln(out, "&mut ss_len,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "ct.truncate(ct_len);");
    gen_writeln(out, "ss.truncate(ss_len);");
    gen_writeln(out, "Ok((ct, ss))");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* KEM Decaps */
    gen_writeln(out, "/// Decapsulate to recover shared secret");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Arguments");
    gen_writeln(out, "/// * `algorithm` - The KEM algorithm");
    gen_writeln(out, "/// * `ct` - The ciphertext");
    gen_writeln(out, "/// * `sk` - The secret key");
    gen_writeln(out, "///");
    gen_writeln(out, "/// # Returns");
    gen_writeln(out, "/// The shared secret");
    gen_writeln(out, "pub fn kem_decaps(&self, algorithm: ffi::KemAlgorithm, ct: &[u8], sk: &[u8]) -> Result<Vec<u8>> {");
    gen_indent(out);
    gen_writeln(out, "let mut ss = vec![0u8; 64];");
    gen_writeln(out, "let mut ss_len: usize = ss.len();");
    gen_newline(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_kem_decaps(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "ct.as_ptr(),");
    gen_writeln(out, "ct.len(),");
    gen_writeln(out, "sk.as_ptr(),");
    gen_writeln(out, "sk.len(),");
    gen_writeln(out, "ss.as_mut_ptr(),");
    gen_writeln(out, "&mut ss_len,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "ss.truncate(ss_len);");
    gen_writeln(out, "Ok(ss)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Sign Keygen */
    gen_writeln(out, "/// Generate a signature keypair");
    gen_writeln(out, "pub fn sign_keygen(&self, algorithm: ffi::SignAlgorithm) -> Result<(Vec<u8>, Vec<u8>)> {");
    gen_indent(out);
    gen_writeln(out, "let mut pk = vec![0u8; 4096];");
    gen_writeln(out, "let mut sk = vec![0u8; 8192];");
    gen_writeln(out, "let mut pk_len: usize = pk.len();");
    gen_writeln(out, "let mut sk_len: usize = sk.len();");
    gen_newline(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_sign_keygen(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "pk.as_mut_ptr(),");
    gen_writeln(out, "&mut pk_len,");
    gen_writeln(out, "sk.as_mut_ptr(),");
    gen_writeln(out, "&mut sk_len,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "pk.truncate(pk_len);");
    gen_writeln(out, "sk.truncate(sk_len);");
    gen_writeln(out, "Ok((pk, sk))");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Sign */
    gen_writeln(out, "/// Sign a message");
    gen_writeln(out, "pub fn sign(&self, algorithm: ffi::SignAlgorithm, msg: &[u8], sk: &[u8]) -> Result<Vec<u8>> {");
    gen_indent(out);
    gen_writeln(out, "let mut sig = vec![0u8; 8192];");
    gen_writeln(out, "let mut sig_len: usize = sig.len();");
    gen_newline(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_sign(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "msg.as_ptr(),");
    gen_writeln(out, "msg.len(),");
    gen_writeln(out, "sk.as_ptr(),");
    gen_writeln(out, "sk.len(),");
    gen_writeln(out, "sig.as_mut_ptr(),");
    gen_writeln(out, "&mut sig_len,");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "sig.truncate(sig_len);");
    gen_writeln(out, "Ok(sig)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Verify */
    gen_writeln(out, "/// Verify a signature");
    gen_writeln(out, "pub fn verify(&self, algorithm: ffi::SignAlgorithm, msg: &[u8], sig: &[u8], pk: &[u8]) -> Result<bool> {");
    gen_indent(out);
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_verify(");
    gen_indent(out);
    gen_writeln(out, "self.handle,");
    gen_writeln(out, "algorithm as i32,");
    gen_writeln(out, "msg.as_ptr(),");
    gen_writeln(out, "msg.len(),");
    gen_writeln(out, "sig.as_ptr(),");
    gen_writeln(out, "sig.len(),");
    gen_writeln(out, "pk.as_ptr(),");
    gen_writeln(out, "pk.len(),");
    gen_dedent(out);
    gen_writeln(out, ")");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_newline(out);
    gen_writeln(out, "// 0 = success (valid), positive = invalid, negative = error");
    gen_writeln(out, "if result < 0 {");
    gen_indent(out);
    gen_writeln(out, "check_result(result)?;");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_writeln(out, "Ok(result == 0)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    /* Random */
    gen_writeln(out, "/// Generate random bytes using QRNG");
    gen_writeln(out, "pub fn random(&self, len: usize) -> Result<Vec<u8>> {");
    gen_indent(out);
    gen_writeln(out, "let mut buf = vec![0u8; len];");
    gen_writeln(out, "let result = unsafe {");
    gen_indent(out);
    gen_writeln(out, "ffi::quac_random(self.handle, buf.as_mut_ptr(), len)");
    gen_dedent(out);
    gen_writeln(out, "};");
    gen_writeln(out, "check_result(result)?;");
    gen_writeln(out, "Ok(buf)");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "/// Get the raw device handle");
    gen_writeln(out, "pub fn as_raw(&self) -> ffi::QuacDevice {");
    gen_indent(out);
    gen_writeln(out, "self.handle");
    gen_dedent(out);
    gen_writeln(out, "}");

    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);

    gen_writeln(out, "impl Drop for Device {");
    gen_indent(out);
    gen_writeln(out, "fn drop(&mut self) {");
    gen_indent(out);
    gen_writeln(out, "if !self.handle.is_null() {");
    gen_indent(out);
    gen_writeln(out, "unsafe { ffi::quac_close_device(self.handle); }");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_dedent(out);
    gen_writeln(out, "}");
    gen_newline(out);
}

/*=============================================================================
 * Main Generator Entry Point
 *=============================================================================*/

int generate_rust(const parsed_api_t *api, const generator_config_t *config)
{
    if (!api || !config)
        return -1;

    /* Generate ffi.rs */
    char path[1024];
    snprintf(path, sizeof(path), "%s/ffi.rs", config->output_dir);

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

    gen_write_file_header(out, "ffi.rs", "Raw FFI bindings for QUAC 100 SDK", TARGET_RUST);

    gen_writeln(out, "#![allow(non_camel_case_types)]");
    gen_writeln(out, "#![allow(non_snake_case)]");
    gen_writeln(out, "#![allow(dead_code)]");
    gen_newline(out);

    generate_ffi_imports(out);
    generate_ffi_type_aliases(out);

    /* Constants */
    gen_writeln(out, "// Constants");
    for (int i = 0; i < api->constant_count; i++)
    {
        const parsed_constant_t *c = &api->constants[i];
        if (strncmp(c->name, "QUAC_", 5) == 0)
        {
            char const_name[128];
            rust_const_name(c->name, const_name, sizeof(const_name));

            if (c->is_string)
            {
                gen_writeln(out, "pub const %s: &str = \"%s\";", const_name, c->value_str);
            }
            else
            {
                gen_writeln(out, "pub const %s: i32 = %s;", const_name, c->value_str);
            }
        }
    }
    gen_newline(out);

    /* Enums */
    for (int i = 0; i < api->enum_count; i++)
    {
        generate_ffi_enum(out, &api->enums[i]);
    }

    /* Structs */
    for (int i = 0; i < api->struct_count; i++)
    {
        generate_ffi_struct(out, &api->structs[i]);
    }

    /* FFI functions */
    gen_writeln(out, "#[link(name = \"quac100\")]");
    gen_writeln(out, "extern \"C\" {");
    for (int i = 0; i < api->function_count; i++)
    {
        generate_ffi_function(out, &api->functions[i]);
    }
    gen_writeln(out, "}");

    gen_output_destroy(out);

    /* Generate lib.rs */
    snprintf(path, sizeof(path), "%s/lib.rs", config->output_dir);

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

    gen_write_file_header(out, "lib.rs", "Safe Rust bindings for QUAC 100 SDK", TARGET_RUST);

    gen_writeln(out, "//! # QUAC 100 SDK");
    gen_writeln(out, "//!");
    gen_writeln(out, "//! Safe Rust bindings for the QUAC 100 post-quantum cryptographic accelerator.");
    gen_writeln(out, "//!");
    gen_writeln(out, "//! ## Example");
    gen_writeln(out, "//!");
    gen_writeln(out, "//! ```rust,no_run");
    gen_writeln(out, "//! use quac100::{Context, ffi::KemAlgorithm};");
    gen_writeln(out, "//!");
    gen_writeln(out, "//! fn main() -> quac100::Result<()> {");
    gen_writeln(out, "//!     let ctx = Context::new()?;");
    gen_writeln(out, "//!     let device = ctx.open_device(0)?;");
    gen_writeln(out, "//!     let (pk, sk) = device.kem_keygen(KemAlgorithm::MlKem768)?;");
    gen_writeln(out, "//!     let (ct, ss1) = device.kem_encaps(KemAlgorithm::MlKem768, &pk)?;");
    gen_writeln(out, "//!     let ss2 = device.kem_decaps(KemAlgorithm::MlKem768, &ct, &sk)?;");
    gen_writeln(out, "//!     assert_eq!(ss1, ss2);");
    gen_writeln(out, "//!     Ok(())");
    gen_writeln(out, "//! }");
    gen_writeln(out, "//! ```");
    gen_newline(out);

    gen_writeln(out, "pub mod ffi;");
    gen_newline(out);

    gen_writeln(out, "use std::os::raw::c_void;");
    gen_newline(out);

    generate_error_type(out);
    generate_context_wrapper(out);
    generate_device_wrapper(out);

    /* Re-exports */
    gen_writeln(out, "// Re-exports for convenience");
    gen_writeln(out, "pub use ffi::KemAlgorithm;");
    gen_writeln(out, "pub use ffi::SignAlgorithm;");
    gen_writeln(out, "pub use ffi::RandomQuality;");

    gen_output_destroy(out);

    /* Generate Cargo.toml */
    snprintf(path, sizeof(path), "%s/Cargo.toml", config->output_dir);

    if (config->verbose)
    {
        printf("  Generating: %s\n", path);
    }

    out = gen_output_create_file(path);
    if (out)
    {
        gen_writeln(out, "[package]");
        gen_writeln(out, "name = \"quac100\"");
        gen_writeln(out, "version = \"1.0.0\"");
        gen_writeln(out, "edition = \"2021\"");
        gen_writeln(out, "authors = [\"Dyber, Inc.\"]");
        gen_writeln(out, "description = \"Rust bindings for QUAC 100 post-quantum cryptographic accelerator\"");
        gen_writeln(out, "license = \"Proprietary\"");
        gen_writeln(out, "repository = \"https://github.com/dyber/quantacore-sdk\"");
        gen_newline(out);
        gen_writeln(out, "[dependencies]");
        gen_newline(out);
        gen_writeln(out, "[build-dependencies]");
        gen_newline(out);
        gen_writeln(out, "[features]");
        gen_writeln(out, "default = []");
        gen_writeln(out, "async = []");
        gen_output_destroy(out);
    }

    return 0;
}