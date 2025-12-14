/**
 * @file parser.c
 * @brief QUAC Binding Generator - C Header Parser Implementation
 *
 * Simple recursive descent parser for C header files. Extracts:
 * - Function declarations
 * - Struct/union definitions
 * - Enum definitions
 * - Typedef declarations
 * - #define constants
 * - Doxygen documentation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "parser.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

#define INITIAL_CAPACITY 64
#define MAX_LINE_LENGTH 4096
#define MAX_TOKEN_LENGTH 512

/*=============================================================================
 * Token Types
 *=============================================================================*/

typedef enum
{
    TOK_EOF,
    TOK_IDENTIFIER,
    TOK_NUMBER,
    TOK_STRING,
    TOK_CHAR,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LBRACKET,
    TOK_RBRACKET,
    TOK_SEMICOLON,
    TOK_COMMA,
    TOK_STAR,
    TOK_EQUALS,
    TOK_COLON,
    TOK_DOC_COMMENT,
    TOK_PREPROCESSOR,
    TOK_KEYWORD,
    TOK_OTHER
} token_type_t;

typedef struct
{
    token_type_t type;
    char value[MAX_TOKEN_LENGTH];
    int line;
    int column;
} token_t;

/*=============================================================================
 * Lexer State
 *=============================================================================*/

typedef struct
{
    const char *input;
    const char *pos;
    const char *filename;
    int line;
    int column;
    char doc_buffer[PARSER_MAX_DOC];
    bool has_doc;
} lexer_t;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

static void *safe_realloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0)
    {
        fprintf(stderr, "Error: Out of memory\n");
        exit(1);
    }
    return new_ptr;
}

static char *read_file(const char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        fprintf(stderr, "Error: Cannot open '%s': %s\n", filename, strerror(errno));
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = malloc(size + 1);
    if (!content)
    {
        fclose(f);
        return NULL;
    }

    size_t read = fread(content, 1, size, f);
    content[read] = '\0';
    fclose(f);

    return content;
}

/*=============================================================================
 * Lexer Implementation
 *=============================================================================*/

static void lexer_init(lexer_t *lex, const char *content, const char *filename)
{
    lex->input = content;
    lex->pos = content;
    lex->filename = filename;
    lex->line = 1;
    lex->column = 1;
    lex->doc_buffer[0] = '\0';
    lex->has_doc = false;
}

static char lexer_peek(lexer_t *lex)
{
    return *lex->pos;
}

static char lexer_advance(lexer_t *lex)
{
    char c = *lex->pos++;
    if (c == '\n')
    {
        lex->line++;
        lex->column = 1;
    }
    else
    {
        lex->column++;
    }
    return c;
}

static void lexer_skip_whitespace(lexer_t *lex)
{
    while (isspace(lexer_peek(lex)))
    {
        lexer_advance(lex);
    }
}

static void lexer_skip_line_comment(lexer_t *lex)
{
    while (lexer_peek(lex) && lexer_peek(lex) != '\n')
    {
        lexer_advance(lex);
    }
}

static void lexer_skip_block_comment(lexer_t *lex)
{
    lexer_advance(lex); /* Skip * */

    while (lexer_peek(lex))
    {
        if (lexer_peek(lex) == '*')
        {
            lexer_advance(lex);
            if (lexer_peek(lex) == '/')
            {
                lexer_advance(lex);
                return;
            }
        }
        else
        {
            lexer_advance(lex);
        }
    }
}

static void lexer_read_doc_comment(lexer_t *lex)
{
    /* Already past /** or /*! */
    char *doc = lex->doc_buffer;
    size_t len = 0;
    size_t max = sizeof(lex->doc_buffer) - 1;

    while (lexer_peek(lex) && len < max)
    {
        if (lexer_peek(lex) == '*')
        {
            lexer_advance(lex);
            if (lexer_peek(lex) == '/')
            {
                lexer_advance(lex);
                break;
            }
            if (len < max)
                doc[len++] = '*';
        }
        else
        {
            char c = lexer_advance(lex);
            /* Skip leading * on lines */
            if (c == '\n')
            {
                if (len < max)
                    doc[len++] = c;
                lexer_skip_whitespace(lex);
                if (lexer_peek(lex) == '*' && lex->pos[1] != '/')
                {
                    lexer_advance(lex);
                    if (lexer_peek(lex) == ' ')
                        lexer_advance(lex);
                }
            }
            else
            {
                if (len < max)
                    doc[len++] = c;
            }
        }
    }

    doc[len] = '\0';

    /* Trim */
    while (len > 0 && isspace(doc[len - 1]))
    {
        doc[--len] = '\0';
    }

    lex->has_doc = len > 0;
}

static token_t lexer_next(lexer_t *lex)
{
    token_t tok = {.line = lex->line, .column = lex->column};

skip_whitespace:
    lexer_skip_whitespace(lex);

    tok.line = lex->line;
    tok.column = lex->column;

    char c = lexer_peek(lex);

    if (!c)
    {
        tok.type = TOK_EOF;
        strcpy(tok.value, "");
        return tok;
    }

    /* Comments */
    if (c == '/')
    {
        lexer_advance(lex);
        if (lexer_peek(lex) == '/')
        {
            /* Check for /// doc comment */
            lexer_advance(lex);
            if (lexer_peek(lex) == '/')
            {
                lexer_advance(lex);
                /* Read doc comment to end of line */
                char *doc = lex->doc_buffer;
                size_t len = 0;
                if (lexer_peek(lex) == ' ')
                    lexer_advance(lex);
                while (lexer_peek(lex) && lexer_peek(lex) != '\n' &&
                       len < sizeof(lex->doc_buffer) - 1)
                {
                    doc[len++] = lexer_advance(lex);
                }
                doc[len] = '\0';
                lex->has_doc = len > 0;
            }
            lexer_skip_line_comment(lex);
            goto skip_whitespace;
        }
        else if (lexer_peek(lex) == '*')
        {
            lexer_advance(lex);
            /* Check for /** doc comment */
            if (lexer_peek(lex) == '*' || lexer_peek(lex) == '!')
            {
                lexer_advance(lex);
                lexer_read_doc_comment(lex);
            }
            else
            {
                lexer_skip_block_comment(lex);
            }
            goto skip_whitespace;
        }
        else
        {
            tok.type = TOK_OTHER;
            strcpy(tok.value, "/");
            return tok;
        }
    }

    /* Preprocessor */
    if (c == '#')
    {
        tok.type = TOK_PREPROCESSOR;
        int i = 0;
        while (lexer_peek(lex) && lexer_peek(lex) != '\n' && i < MAX_TOKEN_LENGTH - 1)
        {
            /* Handle line continuation */
            if (lexer_peek(lex) == '\\')
            {
                lexer_advance(lex);
                if (lexer_peek(lex) == '\n')
                {
                    lexer_advance(lex);
                    continue;
                }
                tok.value[i++] = '\\';
            }
            tok.value[i++] = lexer_advance(lex);
        }
        tok.value[i] = '\0';
        return tok;
    }

    /* Identifiers and keywords */
    if (isalpha(c) || c == '_')
    {
        int i = 0;
        while ((isalnum(lexer_peek(lex)) || lexer_peek(lex) == '_') &&
               i < MAX_TOKEN_LENGTH - 1)
        {
            tok.value[i++] = lexer_advance(lex);
        }
        tok.value[i] = '\0';

        /* Check for keywords */
        static const char *keywords[] = {
            "typedef", "struct", "union", "enum", "const", "volatile",
            "static", "extern", "inline", "void", "char", "short", "int",
            "long", "float", "double", "signed", "unsigned", "bool",
            "_Bool", "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
            "int8_t", "int16_t", "int32_t", "int64_t", "true", "false",
            NULL};

        tok.type = TOK_IDENTIFIER;
        for (int j = 0; keywords[j]; j++)
        {
            if (strcmp(tok.value, keywords[j]) == 0)
            {
                tok.type = TOK_KEYWORD;
                break;
            }
        }

        return tok;
    }

    /* Numbers */
    if (isdigit(c) || (c == '.' && isdigit(lex->pos[1])))
    {
        tok.type = TOK_NUMBER;
        int i = 0;

        /* Hex */
        if (c == '0' && (lex->pos[1] == 'x' || lex->pos[1] == 'X'))
        {
            tok.value[i++] = lexer_advance(lex);
            tok.value[i++] = lexer_advance(lex);
            while (isxdigit(lexer_peek(lex)) && i < MAX_TOKEN_LENGTH - 1)
            {
                tok.value[i++] = lexer_advance(lex);
            }
        }
        else
        {
            while ((isdigit(lexer_peek(lex)) || lexer_peek(lex) == '.' ||
                    lexer_peek(lex) == 'e' || lexer_peek(lex) == 'E') &&
                   i < MAX_TOKEN_LENGTH - 1)
            {
                tok.value[i++] = lexer_advance(lex);
            }
        }

        /* Suffix */
        while ((lexer_peek(lex) == 'u' || lexer_peek(lex) == 'U' ||
                lexer_peek(lex) == 'l' || lexer_peek(lex) == 'L' ||
                lexer_peek(lex) == 'f' || lexer_peek(lex) == 'F') &&
               i < MAX_TOKEN_LENGTH - 1)
        {
            tok.value[i++] = lexer_advance(lex);
        }

        tok.value[i] = '\0';
        return tok;
    }

    /* String */
    if (c == '"')
    {
        tok.type = TOK_STRING;
        lexer_advance(lex);
        int i = 0;
        while (lexer_peek(lex) && lexer_peek(lex) != '"' && i < MAX_TOKEN_LENGTH - 1)
        {
            if (lexer_peek(lex) == '\\')
            {
                tok.value[i++] = lexer_advance(lex);
                if (lexer_peek(lex) && i < MAX_TOKEN_LENGTH - 1)
                {
                    tok.value[i++] = lexer_advance(lex);
                }
            }
            else
            {
                tok.value[i++] = lexer_advance(lex);
            }
        }
        tok.value[i] = '\0';
        if (lexer_peek(lex) == '"')
            lexer_advance(lex);
        return tok;
    }

    /* Character */
    if (c == '\'')
    {
        tok.type = TOK_CHAR;
        lexer_advance(lex);
        int i = 0;
        while (lexer_peek(lex) && lexer_peek(lex) != '\'' && i < MAX_TOKEN_LENGTH - 1)
        {
            if (lexer_peek(lex) == '\\')
            {
                tok.value[i++] = lexer_advance(lex);
                if (lexer_peek(lex) && i < MAX_TOKEN_LENGTH - 1)
                {
                    tok.value[i++] = lexer_advance(lex);
                }
            }
            else
            {
                tok.value[i++] = lexer_advance(lex);
            }
        }
        tok.value[i] = '\0';
        if (lexer_peek(lex) == '\'')
            lexer_advance(lex);
        return tok;
    }

    /* Single character tokens */
    lexer_advance(lex);
    tok.value[0] = c;
    tok.value[1] = '\0';

    switch (c)
    {
    case '(':
        tok.type = TOK_LPAREN;
        break;
    case ')':
        tok.type = TOK_RPAREN;
        break;
    case '{':
        tok.type = TOK_LBRACE;
        break;
    case '}':
        tok.type = TOK_RBRACE;
        break;
    case '[':
        tok.type = TOK_LBRACKET;
        break;
    case ']':
        tok.type = TOK_RBRACKET;
        break;
    case ';':
        tok.type = TOK_SEMICOLON;
        break;
    case ',':
        tok.type = TOK_COMMA;
        break;
    case '*':
        tok.type = TOK_STAR;
        break;
    case '=':
        tok.type = TOK_EQUALS;
        break;
    case ':':
        tok.type = TOK_COLON;
        break;
    default:
        tok.type = TOK_OTHER;
        break;
    }

    return tok;
}

/*=============================================================================
 * Parser State
 *=============================================================================*/

typedef struct
{
    lexer_t lex;
    token_t current;
    token_t lookahead;
    parsed_api_t *api;
    char pending_doc[PARSER_MAX_DOC];
} parser_state_t;

static void parser_advance(parser_state_t *p)
{
    /* Save doc comment if present */
    if (p->lex.has_doc)
    {
        strncpy(p->pending_doc, p->lex.doc_buffer, PARSER_MAX_DOC - 1);
        p->lex.has_doc = false;
    }

    p->current = p->lookahead;
    p->lookahead = lexer_next(&p->lex);
}

static bool parser_check(parser_state_t *p, token_type_t type)
{
    return p->current.type == type;
}

static bool parser_check_keyword(parser_state_t *p, const char *keyword)
{
    return p->current.type == TOK_KEYWORD && strcmp(p->current.value, keyword) == 0;
}

static bool parser_match(parser_state_t *p, token_type_t type)
{
    if (parser_check(p, type))
    {
        parser_advance(p);
        return true;
    }
    return false;
}

static void consume_doc(parser_state_t *p, char *dest, size_t size)
{
    if (p->pending_doc[0])
    {
        strncpy(dest, p->pending_doc, size - 1);
        dest[size - 1] = '\0';
        p->pending_doc[0] = '\0';
    }
    else
    {
        dest[0] = '\0';
    }
}

/*=============================================================================
 * Type Parsing
 *=============================================================================*/

static void parse_type(parser_state_t *p, parsed_type_t *type)
{
    memset(type, 0, sizeof(*type));
    type->kind = TYPE_UNKNOWN;

    /* Qualifiers */
    while (parser_check_keyword(p, "const") ||
           parser_check_keyword(p, "volatile") ||
           parser_check_keyword(p, "unsigned") ||
           parser_check_keyword(p, "signed"))
    {
        if (strcmp(p->current.value, "const") == 0)
        {
            type->qualifiers |= QUAL_CONST;
        }
        else if (strcmp(p->current.value, "volatile") == 0)
        {
            type->qualifiers |= QUAL_VOLATILE;
        }
        else if (strcmp(p->current.value, "unsigned") == 0)
        {
            type->qualifiers |= QUAL_UNSIGNED;
        }
        else if (strcmp(p->current.value, "signed") == 0)
        {
            type->qualifiers |= QUAL_SIGNED;
        }
        parser_advance(p);
    }

    /* Base type */
    if (parser_check_keyword(p, "void"))
    {
        type->kind = TYPE_VOID;
        strcpy(type->name, "void");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "bool") || parser_check_keyword(p, "_Bool"))
    {
        type->kind = TYPE_BOOL;
        strcpy(type->name, "bool");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "char"))
    {
        type->kind = TYPE_CHAR;
        strcpy(type->name, "char");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "int"))
    {
        type->kind = TYPE_INT32;
        strcpy(type->name, "int");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "long"))
    {
        type->kind = TYPE_INT64;
        strcpy(type->name, "long");
        parser_advance(p);
        if (parser_check_keyword(p, "long"))
        {
            parser_advance(p);
        }
    }
    else if (parser_check_keyword(p, "short"))
    {
        type->kind = TYPE_INT16;
        strcpy(type->name, "short");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "float"))
    {
        type->kind = TYPE_FLOAT;
        strcpy(type->name, "float");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "double"))
    {
        type->kind = TYPE_DOUBLE;
        strcpy(type->name, "double");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "size_t"))
    {
        type->kind = TYPE_SIZE;
        strcpy(type->name, "size_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "uint8_t"))
    {
        type->kind = TYPE_UINT8;
        strcpy(type->name, "uint8_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "uint16_t"))
    {
        type->kind = TYPE_UINT16;
        strcpy(type->name, "uint16_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "uint32_t"))
    {
        type->kind = TYPE_UINT32;
        strcpy(type->name, "uint32_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "uint64_t"))
    {
        type->kind = TYPE_UINT64;
        strcpy(type->name, "uint64_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "int8_t"))
    {
        type->kind = TYPE_INT8;
        strcpy(type->name, "int8_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "int16_t"))
    {
        type->kind = TYPE_INT16;
        strcpy(type->name, "int16_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "int32_t"))
    {
        type->kind = TYPE_INT32;
        strcpy(type->name, "int32_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "int64_t"))
    {
        type->kind = TYPE_INT64;
        strcpy(type->name, "int64_t");
        parser_advance(p);
    }
    else if (parser_check_keyword(p, "struct"))
    {
        type->kind = TYPE_STRUCT;
        parser_advance(p);
        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(type->name, p->current.value);
            parser_advance(p);
        }
    }
    else if (parser_check_keyword(p, "union"))
    {
        type->kind = TYPE_UNION;
        parser_advance(p);
        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(type->name, p->current.value);
            parser_advance(p);
        }
    }
    else if (parser_check_keyword(p, "enum"))
    {
        type->kind = TYPE_ENUM;
        parser_advance(p);
        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(type->name, p->current.value);
            parser_advance(p);
        }
    }
    else if (parser_check(p, TOK_IDENTIFIER))
    {
        type->kind = TYPE_TYPEDEF;
        strcpy(type->name, p->current.value);
        parser_advance(p);
    }

    /* Apply unsigned/signed */
    if (type->qualifiers & QUAL_UNSIGNED)
    {
        if (type->kind == TYPE_CHAR)
            type->kind = TYPE_UINT8;
        else if (type->kind == TYPE_INT16)
            type->kind = TYPE_UINT16;
        else if (type->kind == TYPE_INT32)
            type->kind = TYPE_UINT32;
        else if (type->kind == TYPE_INT64)
            type->kind = TYPE_UINT64;
    }

    /* Pointer */
    while (parser_match(p, TOK_STAR))
    {
        type->pointer_depth++;
    }

    if (type->pointer_depth > 0 && type->kind != TYPE_POINTER)
    {
        strcpy(type->base_type, type->name);
        type->kind = TYPE_POINTER;
    }

    /* Const after * */
    if (parser_check_keyword(p, "const"))
    {
        type->qualifiers |= QUAL_CONST;
        parser_advance(p);
    }
}

/*=============================================================================
 * Declaration Parsing
 *=============================================================================*/

static void ensure_function_capacity(parsed_api_t *api)
{
    if (api->function_count >= api->function_capacity)
    {
        api->function_capacity = api->function_capacity ? api->function_capacity * 2 : INITIAL_CAPACITY;
        api->functions = safe_realloc(api->functions,
                                      api->function_capacity * sizeof(parsed_function_t));
    }
}

static void ensure_enum_capacity(parsed_api_t *api)
{
    if (api->enum_count >= api->enum_capacity)
    {
        api->enum_capacity = api->enum_capacity ? api->enum_capacity * 2 : INITIAL_CAPACITY;
        api->enums = safe_realloc(api->enums,
                                  api->enum_capacity * sizeof(parsed_enum_t));
    }
}

static void ensure_struct_capacity(parsed_api_t *api)
{
    if (api->struct_count >= api->struct_capacity)
    {
        api->struct_capacity = api->struct_capacity ? api->struct_capacity * 2 : INITIAL_CAPACITY;
        api->structs = safe_realloc(api->structs,
                                    api->struct_capacity * sizeof(parsed_struct_t));
    }
}

static void ensure_typedef_capacity(parsed_api_t *api)
{
    if (api->typedef_count >= api->typedef_capacity)
    {
        api->typedef_capacity = api->typedef_capacity ? api->typedef_capacity * 2 : INITIAL_CAPACITY;
        api->typedefs = safe_realloc(api->typedefs,
                                     api->typedef_capacity * sizeof(parsed_typedef_t));
    }
}

static void ensure_constant_capacity(parsed_api_t *api)
{
    if (api->constant_count >= api->constant_capacity)
    {
        api->constant_capacity = api->constant_capacity ? api->constant_capacity * 2 : INITIAL_CAPACITY;
        api->constants = safe_realloc(api->constants,
                                      api->constant_capacity * sizeof(parsed_constant_t));
    }
}

static void parse_enum(parser_state_t *p)
{
    ensure_enum_capacity(p->api);
    parsed_enum_t *e = &p->api->enums[p->api->enum_count];
    memset(e, 0, sizeof(*e));

    consume_doc(p, e->doc, sizeof(e->doc));

    parser_advance(p); /* Skip 'enum' */

    /* Name */
    if (parser_check(p, TOK_IDENTIFIER))
    {
        strcpy(e->name, p->current.value);
        parser_advance(p);
    }

    if (!parser_match(p, TOK_LBRACE))
    {
        return; /* Forward declaration */
    }

    /* Values */
    int64_t next_value = 0;

    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF))
    {
        if (e->value_count >= PARSER_MAX_ENUM_VALUES)
            break;

        parsed_enum_value_t *v = &e->values[e->value_count];
        memset(v, 0, sizeof(*v));

        consume_doc(p, v->doc, sizeof(v->doc));

        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(v->name, p->current.value);
            parser_advance(p);

            if (parser_match(p, TOK_EQUALS))
            {
                v->value_explicit = true;
                if (parser_check(p, TOK_NUMBER))
                {
                    v->value = strtoll(p->current.value, NULL, 0);
                    next_value = v->value + 1;
                    parser_advance(p);
                }
                else
                {
                    /* Expression - just skip */
                    while (!parser_check(p, TOK_COMMA) && !parser_check(p, TOK_RBRACE))
                    {
                        parser_advance(p);
                    }
                }
            }
            else
            {
                v->value = next_value++;
            }

            e->value_count++;

            /* Check for flags pattern */
            if (v->value_explicit && (v->value & (v->value - 1)) == 0 && v->value > 0)
            {
                e->is_flags = true;
            }
        }

        parser_match(p, TOK_COMMA);
    }

    parser_match(p, TOK_RBRACE);

    p->api->enum_count++;
    p->api->type_count++;
}

static void parse_struct(parser_state_t *p, bool is_union)
{
    ensure_struct_capacity(p->api);
    parsed_struct_t *s = &p->api->structs[p->api->struct_count];
    memset(s, 0, sizeof(*s));
    s->is_union = is_union;

    consume_doc(p, s->doc, sizeof(s->doc));

    parser_advance(p); /* Skip 'struct' or 'union' */

    /* Name */
    if (parser_check(p, TOK_IDENTIFIER))
    {
        strcpy(s->name, p->current.value);
        parser_advance(p);
    }

    if (!parser_match(p, TOK_LBRACE))
    {
        s->is_opaque = true;
        p->api->struct_count++;
        p->api->type_count++;
        return;
    }

    /* Fields */
    while (!parser_check(p, TOK_RBRACE) && !parser_check(p, TOK_EOF))
    {
        if (s->field_count >= PARSER_MAX_STRUCT_FIELDS)
            break;

        parsed_field_t *f = &s->fields[s->field_count];
        memset(f, 0, sizeof(*f));

        consume_doc(p, f->doc, sizeof(f->doc));

        parse_type(p, &f->type);

        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(f->name, p->current.value);
            parser_advance(p);
        }

        /* Array */
        if (parser_match(p, TOK_LBRACKET))
        {
            if (parser_check(p, TOK_NUMBER))
            {
                f->type.array_size = atoi(p->current.value);
                parser_advance(p);
            }
            else
            {
                f->type.array_size = -1;
            }
            parser_match(p, TOK_RBRACKET);
        }

        /* Bit field */
        if (parser_match(p, TOK_COLON))
        {
            if (parser_check(p, TOK_NUMBER))
            {
                f->bit_width = atoi(p->current.value);
                parser_advance(p);
            }
        }

        s->field_count++;
        parser_match(p, TOK_SEMICOLON);
    }

    parser_match(p, TOK_RBRACE);

    p->api->struct_count++;
    p->api->type_count++;
}

static void parse_typedef(parser_state_t *p)
{
    char doc[PARSER_MAX_DOC];
    consume_doc(p, doc, sizeof(doc));

    parser_advance(p); /* Skip 'typedef' */

    /* Check for struct/union/enum typedef */
    if (parser_check_keyword(p, "struct"))
    {
        parse_struct(p, false);
        /* Get name after struct definition */
        if (parser_check(p, TOK_IDENTIFIER))
        {
            if (p->api->struct_count > 0)
            {
                parsed_struct_t *s = &p->api->structs[p->api->struct_count - 1];
                if (s->name[0] == '\0')
                {
                    strcpy(s->name, p->current.value);
                }
                if (s->doc[0] == '\0' && doc[0])
                {
                    strcpy(s->doc, doc);
                }
            }
            parser_advance(p);
        }
        parser_match(p, TOK_SEMICOLON);
        return;
    }

    if (parser_check_keyword(p, "union"))
    {
        parse_struct(p, true);
        if (parser_check(p, TOK_IDENTIFIER))
        {
            if (p->api->struct_count > 0)
            {
                parsed_struct_t *s = &p->api->structs[p->api->struct_count - 1];
                if (s->name[0] == '\0')
                {
                    strcpy(s->name, p->current.value);
                }
            }
            parser_advance(p);
        }
        parser_match(p, TOK_SEMICOLON);
        return;
    }

    if (parser_check_keyword(p, "enum"))
    {
        parse_enum(p);
        if (parser_check(p, TOK_IDENTIFIER))
        {
            if (p->api->enum_count > 0)
            {
                parsed_enum_t *e = &p->api->enums[p->api->enum_count - 1];
                if (e->name[0] == '\0')
                {
                    strcpy(e->name, p->current.value);
                }
                if (e->doc[0] == '\0' && doc[0])
                {
                    strcpy(e->doc, doc);
                }
            }
            parser_advance(p);
        }
        parser_match(p, TOK_SEMICOLON);
        return;
    }

    /* Regular typedef */
    ensure_typedef_capacity(p->api);
    parsed_typedef_t *td = &p->api->typedefs[p->api->typedef_count];
    memset(td, 0, sizeof(*td));

    strcpy(td->doc, doc);

    parse_type(p, &td->target_type);

    if (parser_check(p, TOK_IDENTIFIER))
    {
        strcpy(td->name, p->current.value);
        parser_advance(p);
    }

    parser_match(p, TOK_SEMICOLON);

    p->api->typedef_count++;
    p->api->type_count++;
}

static void parse_function(parser_state_t *p, parsed_type_t *return_type, const char *name, const char *doc)
{
    ensure_function_capacity(p->api);
    parsed_function_t *f = &p->api->functions[p->api->function_count];
    memset(f, 0, sizeof(*f));

    f->return_type = *return_type;
    strcpy(f->name, name);
    strcpy(f->doc, doc);

    /* Parameters */
    parser_advance(p); /* Skip '(' */

    while (!parser_check(p, TOK_RPAREN) && !parser_check(p, TOK_EOF))
    {
        if (f->param_count >= PARSER_MAX_PARAMS)
            break;

        parsed_param_t *param = &f->params[f->param_count];
        memset(param, 0, sizeof(*param));

        /* Check for void */
        if (parser_check_keyword(p, "void") && f->param_count == 0)
        {
            parser_advance(p);
            if (parser_check(p, TOK_RPAREN))
                break;
        }

        parse_type(p, &param->type);

        if (parser_check(p, TOK_IDENTIFIER))
        {
            strcpy(param->name, p->current.value);
            parser_advance(p);
        }

        /* Array in parameter */
        if (parser_match(p, TOK_LBRACKET))
        {
            param->type.pointer_depth++;
            while (!parser_check(p, TOK_RBRACKET) && !parser_check(p, TOK_EOF))
            {
                parser_advance(p);
            }
            parser_match(p, TOK_RBRACKET);
        }

        f->param_count++;

        if (!parser_match(p, TOK_COMMA))
            break;
    }

    parser_match(p, TOK_RPAREN);
    parser_match(p, TOK_SEMICOLON);

    p->api->function_count++;
}

static void parse_preprocessor(parser_state_t *p)
{
    const char *line = p->current.value;

    /* Skip # */
    if (*line == '#')
        line++;
    while (isspace(*line))
        line++;

    /* Check for #define */
    if (strncmp(line, "define", 6) == 0)
    {
        line += 6;
        while (isspace(*line))
            line++;

        /* Get name */
        char name[PARSER_MAX_NAME];
        int i = 0;
        while ((isalnum(*line) || *line == '_') && i < PARSER_MAX_NAME - 1)
        {
            name[i++] = *line++;
        }
        name[i] = '\0';

        /* Skip function-like macros */
        if (*line == '(')
        {
            parser_advance(p);
            return;
        }

        while (isspace(*line))
            line++;

        /* Get value */
        if (*line && name[0])
        {
            ensure_constant_capacity(p->api);
            parsed_constant_t *c = &p->api->constants[p->api->constant_count];
            memset(c, 0, sizeof(*c));

            strcpy(c->name, name);
            consume_doc(p, c->doc, sizeof(c->doc));

            /* Copy value */
            strncpy(c->value_str, line, sizeof(c->value_str) - 1);

            /* Try to parse as number */
            if (*line == '"')
            {
                c->is_string = true;
            }
            else if (isdigit(*line) || (*line == '-' && isdigit(line[1])) ||
                     (*line == '0' && (line[1] == 'x' || line[1] == 'X')))
            {
                c->value_int = strtoll(line, NULL, 0);
            }
            else if (*line == '.' || (isdigit(*line) && strchr(line, '.')))
            {
                c->value_float = strtod(line, NULL);
                c->is_float = true;
            }

            p->api->constant_count++;
        }
    }

    parser_advance(p);
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

parsed_api_t *parser_create(void)
{
    parsed_api_t *api = calloc(1, sizeof(parsed_api_t));
    return api;
}

void parser_destroy(parsed_api_t *api)
{
    if (!api)
        return;

    free(api->functions);
    free(api->enums);
    free(api->structs);
    free(api->typedefs);
    free(api->constants);

    for (int i = 0; i < api->source_file_count; i++)
    {
        free(api->source_files[i]);
    }
    free(api->source_files);

    free(api);
}

int parser_parse_header(parsed_api_t *api, const char *filename)
{
    char *content = read_file(filename);
    if (!content)
    {
        return -1;
    }

    int result = parser_parse_string(api, content, filename);
    free(content);
    return result;
}

int parser_parse_string(parsed_api_t *api, const char *content, const char *filename)
{
    if (!api || !content)
        return -1;

    /* Track source file */
    api->source_files = safe_realloc(api->source_files,
                                     (api->source_file_count + 1) * sizeof(char *));
    api->source_files[api->source_file_count++] = strdup(filename ? filename : "<string>");

    parser_state_t p = {0};
    lexer_init(&p.lex, content, filename);
    p.api = api;

    /* Prime the parser */
    p.lookahead = lexer_next(&p.lex);
    parser_advance(&p);

    /* Parse declarations */
    while (!parser_check(&p, TOK_EOF))
    {
        if (parser_check(&p, TOK_PREPROCESSOR))
        {
            parse_preprocessor(&p);
        }
        else if (parser_check_keyword(&p, "typedef"))
        {
            parse_typedef(&p);
        }
        else if (parser_check_keyword(&p, "enum"))
        {
            parse_enum(&p);
            parser_match(&p, TOK_SEMICOLON);
        }
        else if (parser_check_keyword(&p, "struct"))
        {
            parse_struct(&p, false);
            parser_match(&p, TOK_SEMICOLON);
        }
        else if (parser_check_keyword(&p, "union"))
        {
            parse_struct(&p, true);
            parser_match(&p, TOK_SEMICOLON);
        }
        else if (parser_check_keyword(&p, "extern") ||
                 parser_check_keyword(&p, "static") ||
                 parser_check_keyword(&p, "inline"))
        {
            parser_advance(&p);
        }
        else if (parser_check(&p, TOK_KEYWORD) || parser_check(&p, TOK_IDENTIFIER))
        {
            /* Could be function or variable declaration */
            char doc[PARSER_MAX_DOC];
            consume_doc(&p, doc, sizeof(doc));

            parsed_type_t type;
            parse_type(&p, &type);

            if (parser_check(&p, TOK_IDENTIFIER))
            {
                char name[PARSER_MAX_NAME];
                strcpy(name, p.current.value);
                parser_advance(&p);

                if (parser_check(&p, TOK_LPAREN))
                {
                    /* Function */
                    parse_function(&p, &type, name, doc);
                }
                else
                {
                    /* Variable - skip */
                    while (!parser_check(&p, TOK_SEMICOLON) && !parser_check(&p, TOK_EOF))
                    {
                        parser_advance(&p);
                    }
                    parser_match(&p, TOK_SEMICOLON);
                }
            }
            else
            {
                parser_match(&p, TOK_SEMICOLON);
            }
        }
        else
        {
            parser_advance(&p);
        }
    }

    return 0;
}

/*=============================================================================
 * Lookup Functions
 *=============================================================================*/

const parsed_function_t *parser_find_function(const parsed_api_t *api, const char *name)
{
    if (!api || !name)
        return NULL;
    for (int i = 0; i < api->function_count; i++)
    {
        if (strcmp(api->functions[i].name, name) == 0)
        {
            return &api->functions[i];
        }
    }
    return NULL;
}

const parsed_enum_t *parser_find_enum(const parsed_api_t *api, const char *name)
{
    if (!api || !name)
        return NULL;
    for (int i = 0; i < api->enum_count; i++)
    {
        if (strcmp(api->enums[i].name, name) == 0)
        {
            return &api->enums[i];
        }
    }
    return NULL;
}

const parsed_struct_t *parser_find_struct(const parsed_api_t *api, const char *name)
{
    if (!api || !name)
        return NULL;
    for (int i = 0; i < api->struct_count; i++)
    {
        if (strcmp(api->structs[i].name, name) == 0)
        {
            return &api->structs[i];
        }
    }
    return NULL;
}

const parsed_typedef_t *parser_find_typedef(const parsed_api_t *api, const char *name)
{
    if (!api || !name)
        return NULL;
    for (int i = 0; i < api->typedef_count; i++)
    {
        if (strcmp(api->typedefs[i].name, name) == 0)
        {
            return &api->typedefs[i];
        }
    }
    return NULL;
}

const parsed_constant_t *parser_find_constant(const parsed_api_t *api, const char *name)
{
    if (!api || !name)
        return NULL;
    for (int i = 0; i < api->constant_count; i++)
    {
        if (strcmp(api->constants[i].name, name) == 0)
        {
            return &api->constants[i];
        }
    }
    return NULL;
}

/*=============================================================================
 * Type Utilities
 *=============================================================================*/

const char *parser_type_kind_str(c_type_kind_t kind)
{
    static const char *names[] = {
        "void", "bool", "char", "int8", "uint8", "int16", "uint16",
        "int32", "uint32", "int64", "uint64", "size", "float", "double",
        "pointer", "array", "struct", "union", "enum", "function_ptr",
        "typedef", "unknown"};
    return (kind <= TYPE_UNKNOWN) ? names[kind] : "unknown";
}

void parser_format_type(const parsed_type_t *type, char *buffer, size_t size)
{
    if (!type || !buffer || size == 0)
        return;

    char *p = buffer;
    size_t rem = size;
    int written;

    if (type->qualifiers & QUAL_CONST)
    {
        written = snprintf(p, rem, "const ");
        p += written;
        rem -= written;
    }

    written = snprintf(p, rem, "%s", type->name);
    p += written;
    rem -= written;

    for (int i = 0; i < type->pointer_depth && rem > 1; i++)
    {
        *p++ = '*';
        rem--;
    }
    *p = '\0';
}

bool parser_type_is_primitive(const parsed_type_t *type)
{
    if (!type)
        return false;
    return type->kind >= TYPE_VOID && type->kind <= TYPE_DOUBLE &&
           type->pointer_depth == 0;
}

bool parser_type_is_pointer(const parsed_type_t *type)
{
    return type && type->pointer_depth > 0;
}

const parsed_type_t *parser_resolve_typedef(const parsed_api_t *api,
                                            const parsed_type_t *type)
{
    if (!api || !type)
        return type;
    if (type->kind != TYPE_TYPEDEF)
        return type;

    const parsed_typedef_t *td = parser_find_typedef(api, type->name);
    if (!td)
        return type;

    return parser_resolve_typedef(api, &td->target_type);
}