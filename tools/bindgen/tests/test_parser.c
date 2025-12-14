/**
 * @file test_parser.c
 * @brief Unit tests for the QUAC bindgen C header parser
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "parser.h"
#include "types.h"

/*=============================================================================
 * Test Framework
 *=============================================================================*/

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name)                     \
    do                                     \
    {                                      \
        printf("  Running %s... ", #name); \
        g_tests_run++;                     \
        test_##name();                     \
        g_tests_passed++;                  \
        printf("PASSED\n");                \
    } while (0)

#define ASSERT(cond)                                      \
    do                                                    \
    {                                                     \
        if (!(cond))                                      \
        {                                                 \
            printf("FAILED\n");                           \
            printf("    Assertion failed: %s\n", #cond);  \
            printf("    at %s:%d\n", __FILE__, __LINE__); \
            g_tests_failed++;                             \
            return;                                       \
        }                                                 \
    } while (0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NE(a, b) ASSERT((a) != (b))
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)
#define ASSERT_NOT_NULL(p) ASSERT((p) != NULL)
#define ASSERT_NULL(p) ASSERT((p) == NULL)

/*=============================================================================
 * Test Data
 *=============================================================================*/

static const char *TEST_HEADER_ENUM =
    "/** Test enum for results */\n"
    "typedef enum {\n"
    "    QUAC_SUCCESS = 0,\n"
    "    QUAC_ERROR_INVALID = -1,\n"
    "    QUAC_ERROR_TIMEOUT = -2\n"
    "} quac_result_t;\n";

static const char *TEST_HEADER_STRUCT =
    "/** Device information structure */\n"
    "typedef struct {\n"
    "    uint32_t vendor_id;\n"
    "    uint32_t device_id;\n"
    "    char name[64];\n"
    "    bool enabled;\n"
    "} quac_device_info_t;\n";

static const char *TEST_HEADER_FUNCTION =
    "/**\n"
    " * Initialize the QUAC SDK\n"
    " * @param ctx Context pointer\n"
    " * @return Result code\n"
    " */\n"
    "quac_result_t quac_init(quac_context_t* ctx);\n"
    "\n"
    "/** Get device count */\n"
    "quac_result_t quac_get_device_count(quac_context_t ctx, uint32_t* count);\n";

static const char *TEST_HEADER_CONSTANT =
    "#define QUAC_VERSION_MAJOR 1\n"
    "#define QUAC_VERSION_MINOR 0\n"
    "#define QUAC_VERSION_PATCH 0\n"
    "#define QUAC_VERSION_STRING \"1.0.0\"\n"
    "#define QUAC_MAX_DEVICES 16\n";

static const char *TEST_HEADER_TYPEDEF =
    "typedef void* quac_context_t;\n"
    "typedef void* quac_device_t;\n"
    "typedef uint32_t quac_key_handle_t;\n";

static const char *TEST_HEADER_FLAGS_ENUM =
    "typedef enum {\n"
    "    QUAC_FLAG_NONE = 0,\n"
    "    QUAC_FLAG_ASYNC = 1,\n"
    "    QUAC_FLAG_BATCH = 2,\n"
    "    QUAC_FLAG_SECURE = 4,\n"
    "    QUAC_FLAG_ALL = 7\n"
    "} quac_flags_t;\n";

/*=============================================================================
 * Parser Tests
 *=============================================================================*/

TEST(parser_create_destroy)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);
    ASSERT_EQ(api->function_count, 0);
    ASSERT_EQ(api->enum_count, 0);
    ASSERT_EQ(api->struct_count, 0);
    parser_destroy(api);
}

TEST(parse_enum)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_ENUM, "test_enum.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->enum_count, 1);

    const parsed_enum_t *e = &api->enums[0];
    ASSERT_STR_EQ(e->name, "quac_result_t");
    ASSERT_EQ(e->value_count, 3);

    ASSERT_STR_EQ(e->values[0].name, "QUAC_SUCCESS");
    ASSERT_EQ(e->values[0].value, 0);

    ASSERT_STR_EQ(e->values[1].name, "QUAC_ERROR_INVALID");
    ASSERT_EQ(e->values[1].value, -1);

    ASSERT_STR_EQ(e->values[2].name, "QUAC_ERROR_TIMEOUT");
    ASSERT_EQ(e->values[2].value, -2);

    parser_destroy(api);
}

TEST(parse_flags_enum)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_FLAGS_ENUM, "test_flags.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->enum_count, 1);

    const parsed_enum_t *e = &api->enums[0];
    ASSERT_STR_EQ(e->name, "quac_flags_t");
    /* Parser should detect this is a flags enum */
    ASSERT(e->is_flags);

    parser_destroy(api);
}

TEST(parse_struct)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_STRUCT, "test_struct.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->struct_count, 1);

    const parsed_struct_t *s = &api->structs[0];
    ASSERT_STR_EQ(s->name, "quac_device_info_t");
    ASSERT_EQ(s->field_count, 4);
    ASSERT(!s->is_opaque);
    ASSERT(!s->is_union);

    ASSERT_STR_EQ(s->fields[0].name, "vendor_id");
    ASSERT_EQ(s->fields[0].type.kind, TYPE_UINT32);

    ASSERT_STR_EQ(s->fields[1].name, "device_id");
    ASSERT_EQ(s->fields[1].type.kind, TYPE_UINT32);

    ASSERT_STR_EQ(s->fields[2].name, "name");
    ASSERT_EQ(s->fields[2].type.kind, TYPE_CHAR);
    ASSERT_EQ(s->fields[2].type.array_size, 64);

    ASSERT_STR_EQ(s->fields[3].name, "enabled");
    ASSERT_EQ(s->fields[3].type.kind, TYPE_BOOL);

    parser_destroy(api);
}

TEST(parse_function)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    /* Also need typedef for quac_context_t */
    const char *header =
        "typedef void* quac_context_t;\n"
        "typedef int quac_result_t;\n"
        "quac_result_t quac_init(quac_context_t* ctx);\n"
        "quac_result_t quac_get_device_count(quac_context_t ctx, uint32_t* count);\n";

    int result = parser_parse_string(api, header, "test_func.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->function_count, 2);

    const parsed_function_t *f1 = &api->functions[0];
    ASSERT_STR_EQ(f1->name, "quac_init");
    ASSERT_EQ(f1->param_count, 1);
    ASSERT_STR_EQ(f1->params[0].name, "ctx");

    const parsed_function_t *f2 = &api->functions[1];
    ASSERT_STR_EQ(f2->name, "quac_get_device_count");
    ASSERT_EQ(f2->param_count, 2);

    parser_destroy(api);
}

TEST(parse_constants)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_CONSTANT, "test_const.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->constant_count, 5);

    const parsed_constant_t *c = parser_find_constant(api, "QUAC_VERSION_MAJOR");
    ASSERT_NOT_NULL(c);
    ASSERT_EQ(c->value_int, 1);

    c = parser_find_constant(api, "QUAC_MAX_DEVICES");
    ASSERT_NOT_NULL(c);
    ASSERT_EQ(c->value_int, 16);

    c = parser_find_constant(api, "QUAC_VERSION_STRING");
    ASSERT_NOT_NULL(c);
    ASSERT(c->is_string);

    parser_destroy(api);
}

TEST(parse_typedef)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_TYPEDEF, "test_typedef.h");
    ASSERT_EQ(result, 0);
    ASSERT_EQ(api->typedef_count, 3);

    const parsed_typedef_t *td = parser_find_typedef(api, "quac_context_t");
    ASSERT_NOT_NULL(td);
    ASSERT_EQ(td->target_type.kind, TYPE_POINTER);

    td = parser_find_typedef(api, "quac_key_handle_t");
    ASSERT_NOT_NULL(td);
    ASSERT_EQ(td->target_type.kind, TYPE_UINT32);

    parser_destroy(api);
}

TEST(parser_find_functions)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    const char *header =
        "typedef int quac_result_t;\n"
        "quac_result_t quac_init(void);\n"
        "quac_result_t quac_shutdown(void);\n";

    int result = parser_parse_string(api, header, "test.h");
    ASSERT_EQ(result, 0);

    const parsed_function_t *f = parser_find_function(api, "quac_init");
    ASSERT_NOT_NULL(f);
    ASSERT_STR_EQ(f->name, "quac_init");

    f = parser_find_function(api, "quac_shutdown");
    ASSERT_NOT_NULL(f);

    f = parser_find_function(api, "nonexistent");
    ASSERT_NULL(f);

    parser_destroy(api);
}

TEST(parse_doc_comments)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_ENUM, "test_doc.h");
    ASSERT_EQ(result, 0);

    const parsed_enum_t *e = &api->enums[0];
    /* Check that doc comment was captured */
    ASSERT(strlen(e->doc) > 0);

    parser_destroy(api);
}

/*=============================================================================
 * Type System Tests
 *=============================================================================*/

TEST(type_mapping)
{
    types_init();

    const type_mapping_t *m = types_get_mapping(TYPE_UINT32);
    ASSERT_NOT_NULL(m);
    ASSERT_STR_EQ(m->c_name, "uint32_t");
    ASSERT_STR_EQ(m->python_type, "int");
    ASSERT_STR_EQ(m->rust_type, "u32");

    m = types_get_mapping(TYPE_BOOL);
    ASSERT_NOT_NULL(m);
    ASSERT_STR_EQ(m->python_type, "bool");
    ASSERT_STR_EQ(m->rust_type, "bool");

    types_shutdown();
}

TEST(type_mapping_by_name)
{
    types_init();

    const type_mapping_t *m = types_get_mapping_by_name("uint64_t");
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(m->c_kind, TYPE_UINT64);

    m = types_get_mapping_by_name("nonexistent");
    ASSERT_NULL(m);

    types_shutdown();
}

TEST(quac_type_detection)
{
    ASSERT(types_is_quac_handle("quac_context_t"));
    ASSERT(types_is_quac_handle("quac_device_t"));
    ASSERT(!types_is_quac_handle("uint32_t"));

    ASSERT(types_is_quac_result("quac_result_t"));
    ASSERT(!types_is_quac_result("quac_context_t"));

    ASSERT(types_is_quac_enum("quac_kem_algorithm_t"));
    ASSERT(!types_is_quac_enum("quac_context_t"));
}

/*=============================================================================
 * Integration Tests
 *=============================================================================*/

TEST(parse_multiple_headers)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    int result = parser_parse_string(api, TEST_HEADER_ENUM, "enums.h");
    ASSERT_EQ(result, 0);

    result = parser_parse_string(api, TEST_HEADER_STRUCT, "structs.h");
    ASSERT_EQ(result, 0);

    result = parser_parse_string(api, TEST_HEADER_TYPEDEF, "typedefs.h");
    ASSERT_EQ(result, 0);

    ASSERT_EQ(api->enum_count, 1);
    ASSERT_EQ(api->struct_count, 1);
    ASSERT_EQ(api->typedef_count, 3);
    ASSERT_EQ(api->source_file_count, 3);

    parser_destroy(api);
}

TEST(parse_complex_types)
{
    parsed_api_t *api = parser_create();
    ASSERT_NOT_NULL(api);

    const char *header =
        "typedef struct {\n"
        "    const uint8_t* data;\n"
        "    size_t length;\n"
        "    uint8_t buffer[256];\n"
        "} quac_buffer_t;\n";

    int result = parser_parse_string(api, header, "complex.h");
    ASSERT_EQ(result, 0);

    const parsed_struct_t *s = &api->structs[0];
    ASSERT_EQ(s->field_count, 3);

    /* const uint8_t* data */
    ASSERT_EQ(s->fields[0].type.pointer_depth, 1);
    ASSERT(s->fields[0].type.qualifiers & QUAL_CONST);

    /* size_t length */
    ASSERT_EQ(s->fields[1].type.kind, TYPE_SIZE);

    /* uint8_t buffer[256] */
    ASSERT_EQ(s->fields[2].type.array_size, 256);

    parser_destroy(api);
}

/*=============================================================================
 * Main
 *=============================================================================*/

int main(void)
{
    printf("Running bindgen parser tests...\n\n");

    printf("Parser tests:\n");
    RUN_TEST(parser_create_destroy);
    RUN_TEST(parse_enum);
    RUN_TEST(parse_flags_enum);
    RUN_TEST(parse_struct);
    RUN_TEST(parse_function);
    RUN_TEST(parse_constants);
    RUN_TEST(parse_typedef);
    RUN_TEST(parser_find_functions);
    RUN_TEST(parse_doc_comments);

    printf("\nType system tests:\n");
    RUN_TEST(type_mapping);
    RUN_TEST(type_mapping_by_name);
    RUN_TEST(quac_type_detection);

    printf("\nIntegration tests:\n");
    RUN_TEST(parse_multiple_headers);
    RUN_TEST(parse_complex_types);

    printf("\n=================================\n");
    printf("Tests run: %d\n", g_tests_run);
    printf("Tests passed: %d\n", g_tests_passed);
    printf("Tests failed: %d\n", g_tests_failed);
    printf("=================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}