#include "redismodule.h"
#include "tairdoc.h"
#include "cJSON/cJSON.h"
#include "cJSON/cJSON_Utils.h"

#include <strings.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <assert.h>

static RedisModuleType *TairDocType;
#define TAIRDOC_ENC_VER 0

void debugPrint(RedisModuleCtx *ctx, char *name, cJSON *root) {
    REDISMODULE_NOT_USED(ctx);
    REDISMODULE_NOT_USED(name);
    REDISMODULE_NOT_USED(root);
#ifdef JSON_DEBUG
    char *print = cJSON_Print(root);
    RedisModule_Log(ctx, "notice", "%s : %s", name, print);
    RedisModule_Free(print);
#endif
}

/* ========================== TairDoc function methods ======================= */

#define PATH_TO_POINTER(ctx, path, rpointer)                              \
    if (pathToPointer((ctx), (path), &(rpointer)) != 0) {                 \
        RedisModule_ReplyWithError(ctx, TAIRDOC_PATH_TO_POINTER_ERROR);    \
        return REDISMODULE_ERR;                                           \
    }

/*
 * create node from json
 */
int createNodeFromJson(cJSON **node, const char *json, RedisModuleString **jerr) {
    *node = cJSON_ParseWithOpts(json, NULL, 1);
    if (*node == NULL) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR json lexer error at position '%s'", cJSON_GetErrorPtr());
        return REDISMODULE_ERR;
    }

    return REDISMODULE_OK;
}

int composePatch(cJSON *const patches, const unsigned char *const operation, const char *const path,
                 const cJSON *const value) {
    cJSON *patch = NULL;
    if ((patches == NULL) || (operation == NULL) || (path == NULL)) {
        return REDISMODULE_ERR;
    }

    patch = cJSON_CreateObject();
    if (patch == NULL) {
        return REDISMODULE_ERR;
    }
    cJSON_AddItemToObject(patch, "op", cJSON_CreateString((const char *) operation));
    cJSON_AddItemToObject(patch, "path", cJSON_CreateString(path));
    if (value != NULL) {
        cJSON_AddItemToObject(patch, "value", cJSON_Duplicate(value, 1));
    }
    cJSON_AddItemToArray(patches, patch);
    return REDISMODULE_OK;
}

int applyPatch(cJSON *const object, const cJSON *const patches, RedisModuleString **jerr) {
    int ret = cJSONUtils_ApplyPatchesCaseSensitive(object, patches);
    if (ret == 0) {
        goto ok;
    }

    if (ret == 1) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR patches is not array");
        goto error;
    } else if (ret == 2) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR malformed patch, path is not string");
        goto error;
    } else if (ret == 3) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR patch opcode is illegal");
        goto error;
    } else if (ret == 4 || ret == 5) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR missing 'from' for copy or move");
        goto error;
    } else if (ret == 7) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR missing 'value' for add or replace");
        goto error;
    } else if (ret == 8 || ret == 6) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR may be oom");
        goto error;
    } else if (ret == 9) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR could not find object to add, please check path");
        goto error;
    } else if (ret == 10) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR insert item in array error, index error");
        goto error;
    } else if (ret == 11) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR array index error");
        goto error;
    } else if (ret == 13) {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR old item is null for remove or replace");
        goto error;
    } else {
        *jerr = RedisModule_CreateStringPrintf(NULL, "ERR apply patch unknow error");
        goto error;
    }

    error:
    return REDISMODULE_ERR;

    ok:
    return REDISMODULE_OK;
}

/* Returns the string representation json node's type. */
static inline char *jsonNodeType(const int nt) {
    static char *types[] = {"boolean", "null", "number", "string", "array", "object", "raw", "reference", "const"};
    switch (nt) {
        case cJSON_False:
        case cJSON_True:
            return types[0];
        case cJSON_NULL:
            return types[1];
        case cJSON_Number:
            return types[2];
        case cJSON_String:
            return types[3];
        case cJSON_Array:
            return types[4];
        case cJSON_Object:
            return types[5];
        case cJSON_Raw:
            return types[6];
        case cJSON_IsReference:
            return types[7];
        case cJSON_StringIsConst:
            return types[8];
        default:
            return NULL;
    }
}

int pathToPointer(RedisModuleCtx *ctx, const char *jpa, RedisModuleString **rpointer) {
    char *jpo = NULL;

    if (jpa[0] != '.' && jpa[0] != '[' && jpa[0] != '$') {
        *rpointer = RedisModule_CreateString(ctx, jpa, strlen(jpa));
        return 0;
    }

    if (!strcmp(jpa, ".") || !strcmp(jpa, "") || !strcmp(jpa, "$")) {
        *rpointer = RedisModule_CreateString(ctx, "", 0);
        return 0;
    }

    size_t i, j, size;
    size_t len = strlen(jpa), step = 0;
    for (i = 0; i < len; ++i) {
        char c = jpa[i];
        switch (c) {
            case '.':
                jpo = (char *) RedisModule_Realloc(jpo, step + 1);
                memcpy(jpo + step, "/", 1);
                step++;
                break;

            case '[':
                jpo = (char *) RedisModule_Realloc(jpo, step + 1);
                memcpy(jpo + step, "/", 1);
                step++;

                j = i + 1;
                if (jpa[j] == '\"' || jpa[j] == '\'') {
                    ++j;
                    while (j < len && jpa[j] != '\"' && jpa[j] != '\'') ++j;
                    if (j >= len) {
                        goto error;
                    }
                    size = j - i - 2;
                    jpo = (char *) RedisModule_Realloc(jpo, step + size);
                    memcpy(jpo + step, &jpa[i + 2], (size_t) size);
                    step += size;
                    i = j + 1;
                    if (jpa[i] != ']') {
                        goto error;
                    }
                } else if (isdigit(jpa[j]) || jpa[j] == '-') {
                    while (j < len && jpa[j] != ']') ++j;
                    if (j >= len) {
                        goto error;
                    }
                    size = j - i - 1;
                    jpo = (char *) RedisModule_Realloc(jpo, step + size);
                    memcpy(jpo + step, &jpa[i + 1], (size_t) size);
                    step += size;
                    i = j;
                } else {
                    goto error;
                }
                break;

            default:
                j = i + 1;
                while (j < len && jpa[j] != '.' && jpa[j] != '[') ++j;
                size = j - i;
                jpo = (char *) RedisModule_Realloc(jpo, step + size);
                memcpy(jpo + step, &jpa[i], (size_t) size);
                i += size - 1;
                step += size;
        }
    }

    jpo = (char *) RedisModule_Realloc(jpo, step + 1);
    jpo[step] = '\0';
    *rpointer = RedisModule_CreateString(ctx, jpo, strlen(jpo));
    RedisModule_Free(jpo);
    return 0;

    error:
    if (jpo) RedisModule_Free(jpo);
    return -1;
}

/* ========================== TairDoc commands methods ======================= */

/**
 * JSON.SET <key> <path> <json> [NX|XX]
 * Sets the JSON value at `path` in `key`
 *
 * For new Redis keys the `path` must be the root. For existing keys, when the entire `path` exists,
 * the value that it contains is replaced with the `json` value.
 *
 * `NX` - only set the key if it does not already exists
 * `XX` - only set the key if it already exists
 *
 * Reply: Simple String `OK` if executed correctly, or Null Bulk if the specified `NX` or `XX`
 * conditions were not met.
 */
int TairDocSet_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if ((argc < 4) || (argc > 5)) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    RedisModuleString *jerr = NULL;
    int flags = EX_OBJ_SET_NO_FLAGS;
    int isRootPointer = 0, isKeyExists = 0;
    cJSON *root = NULL, *node = NULL, *patches = NULL, *pnode = NULL;

    const char *pointer = RedisModule_StringPtrLen(argv[2], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    if (argc == 5) {
        const char *a = RedisModule_StringPtrLen(argv[4], NULL);
        if (!strncasecmp(a, "nx\0", 3) && !(flags & EX_OBJ_SET_XX)) {
            flags |= EX_OBJ_SET_NX;
        } else if (!strncasecmp(a, "xx\0", 3) && !(flags & EX_OBJ_SET_NX)) {
            flags |= EX_OBJ_SET_XX;
        } else {
            RedisModule_ReplyWithError(ctx, TAIRDOC_SYNTAX_ERROR);
            return REDISMODULE_ERR;
        }
    }

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    int type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        isKeyExists = 0;
        if (flags & EX_OBJ_SET_XX) {
            goto null;
        }
    } else {
        isKeyExists = 1;
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    if (REDISMODULE_OK != createNodeFromJson(&node, RedisModule_StringPtrLen(argv[3], NULL), &jerr)) {
        RedisModule_ReplyWithError(ctx, RedisModule_StringPtrLen(jerr, NULL));
        RedisModule_FreeString(NULL, jerr);
        goto error;
    }
    debugPrint(ctx, "node", node);

    root = isKeyExists ? root : cJSON_Duplicate(node, 1);
    isRootPointer = strcasecmp("", RedisModule_StringPtrLen(rpointer, NULL)) ? 0 : 1;
    if (!isKeyExists) {
        if (!isRootPointer) {
            if (root) cJSON_Delete(root);
            RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NEW_NOT_ROOT);
            goto error;
        }
        // if key not exists, add it.
        RedisModule_ModuleTypeSetValue(key, TairDocType, root);
        goto ok;
    }

    // make a patch and apply
    patches = cJSON_CreateArray();
    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL) {
        if (flags & EX_OBJ_SET_XX) goto null;
        if (REDISMODULE_OK !=
            composePatch(patches, (const unsigned char *) "add", RedisModule_StringPtrLen(rpointer, NULL), node)) {
            RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_JSONOBJECT_ERROR);
            goto error;
        }
    } else {
        if (flags & EX_OBJ_SET_NX) goto null;
        if (REDISMODULE_OK !=
            composePatch(patches, (const unsigned char *) "replace", RedisModule_StringPtrLen(rpointer, NULL), node)) {
            RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_JSONOBJECT_ERROR);
            goto error;
        }
    }
    debugPrint(ctx, "patch", patches);

    if (REDISMODULE_OK != applyPatch(root, patches, &jerr)) {
        RedisModule_ReplyWithError(ctx, RedisModule_StringPtrLen(jerr, NULL));
        RedisModule_FreeString(NULL, jerr);
        goto error;
    }

ok:
    debugPrint(ctx, "root", root);
    RedisModule_ReplyWithSimpleString(ctx, "OK");
    if (node) cJSON_Delete(node);
    if (patches) cJSON_Delete(patches);
    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;

null:
    RedisModule_ReplyWithNull(ctx);
    if (node) cJSON_Delete(node);
    if (patches) cJSON_Delete(patches);
    return REDISMODULE_OK;

error:
    if (node) cJSON_Delete(node);
    if (patches) cJSON_Delete(patches);
    return REDISMODULE_ERR;
}

/**
 * JSON.GET <key> [PATH]
 * Return the value at `path` in JSON serialized form.
 *
 * `key` the key
 * `path` the path of json
 *
 * Reply: Bulk String
 */

int TairDocGet_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 2) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int type = 0, needFree = 0;
    const char *print = NULL, *input = NULL;
    cJSON *root = NULL, *pnode = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithNull(ctx);
        return REDISMODULE_OK;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    if (argc >= 3) {
        input = RedisModule_StringPtrLen(argv[2], NULL);
        if (input[0] == TAIRDOC_JSONPATH_START_DOLLAR) {
            pnode = cJSONUtils_GetPath(root, input);
            needFree = 1;
        } else if (input[0] == TAIRDOC_JSONPOINTER_START) {
            pnode = cJSONUtils_GetPointerCaseSensitive(root, input);
        } else {
            if (!strcmp(input, TAIRDOC_JSONPOINTER_ROOT)) {
                pnode = cJSONUtils_GetPointerCaseSensitive(root, "");
            } else if (input[0] == TAIRDOC_JSONPATH_START_DOT || input[0] == TAIRDOC_JSONPATH_START_SQUARE_BRACKETS) {
                RedisModuleString *rpointer = NULL;
                PATH_TO_POINTER(ctx, input, rpointer)
                pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
            } else {
                RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_PATH_OR_POINTER_ILLEGAL);
                return REDISMODULE_ERR;
            }
        }
    } else {
        pnode = cJSONUtils_GetPointerCaseSensitive(root, TAIRDOC_JSONPOINTER_ROOT);
    }
    if (pnode == NULL) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_PARSE_POINTER);
        goto error;
    }

    print = cJSON_PrintUnformatted(pnode);
    assert(print != NULL);
    RedisModule_ReplyWithStringBuffer(ctx, print, strlen(print));
    if (print) RedisModule_Free((void *) print);
    if (needFree) cJSON_Delete(pnode);
    return REDISMODULE_OK;

error:
    if (needFree) cJSON_Delete(pnode);
    return REDISMODULE_ERR;
}

/**
 * JSON.DEL <key> [path]
 * Delete a value.
 *
 * `path` defaults to root if not provided. Non-existing keys as well as non-existing paths are
 * ignored. Deleting an object's root is equivalent to deleting the key from Redis.
 *
 * Reply: Integer, specifically the number of paths deleted (0 or 1).
 */
int TairDocDel_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 2) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    RedisModuleString *jerr = NULL;
    int isRootPointer = 0, type;
    char *pointer = NULL;
    cJSON *root = NULL, *patches = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, 0);
        return REDISMODULE_OK;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 3 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    isRootPointer = strcasecmp("", RedisModule_StringPtrLen(rpointer, NULL)) ? 0 : 1;

    if (isRootPointer) {
        RedisModule_DeleteKey(key);
        RedisModule_ReplyWithLongLong(ctx, 1);
        RedisModule_ReplicateVerbatim(ctx);
        return REDISMODULE_OK;
    }

    // make a patch and apply
    patches = cJSON_CreateArray();
    if (REDISMODULE_OK !=
        composePatch(patches, (const unsigned char *) "remove", RedisModule_StringPtrLen(rpointer, NULL), NULL)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_JSONOBJECT_ERROR);
        goto error;
    }
    debugPrint(ctx, "patch", patches);

    if (REDISMODULE_OK != applyPatch(root, patches, &jerr)) {
        RedisModule_ReplyWithError(ctx, RedisModule_StringPtrLen(jerr, NULL));
        RedisModule_FreeString(NULL, jerr);
        goto error;
    }

    RedisModule_ReplyWithLongLong(ctx, 1);
    if (patches) cJSON_Delete(patches);
    if (!root->next && !root->prev && !root->child) {
        RedisModule_DeleteKey(key);
    }
    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;

error:
    if (patches) cJSON_Delete(patches);
    return REDISMODULE_ERR;
}

/**
 * JSON.TYPE <key> [path]
 * Reports the type of JSON value at `path`.
 * `path` defaults to root if not provided. If the `key` or `path` do not exist, null is returned.
 * Reply: Simple string, specifically the type.
 */
int TairDocType_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 2) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int type = 0;
    char *print = NULL, *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithNull(ctx);
        return REDISMODULE_OK;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 3 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL) {
        RedisModule_ReplyWithNull(ctx);
        return REDISMODULE_ERR;
    }

    print = jsonNodeType(pnode->type);
    RedisModule_ReplyWithStringBuffer(ctx, print, strlen(print));
    return REDISMODULE_OK;
}

int incrGenericCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc, double incr) {
    char *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL;
    double newvalue = 0;
    int type = 0;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_NO_SUCKKEY_ERROR);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 4 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsNumber(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_NUMBER);
        return REDISMODULE_ERR;
    }

    newvalue = pnode->valuedouble + incr;
    if (isnan(newvalue) || isinf(newvalue)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_INCR_OVERFLOW);
        return REDISMODULE_ERR;
    }

    cJSON_SetNumberHelper(pnode, newvalue);
    char *print = cJSON_PrintUnformatted(pnode);
    RedisModule_ReplyWithStringBuffer(ctx, print, strlen(print));
    RedisModule_Free(print);

    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;
}

/**
 * JSON.INCRBY <key> [path] <value>
 * value range: [-2^53, 2^53] [-9007199254740992, 9007199254740992]
 * Increments the value stored under `path` by `value`.
 * `path` must exist path and must be a number value.
 * Reply: int number, specifically the resulting.
 */
int TairDocIncrBy_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 3) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    long long incr = 0;
    if (REDISMODULE_OK != RedisModule_StringToLongLong(argc == 4 ? argv[3] : argv[2], &incr)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_VALUE_OUTOF_RANGE);
        return REDISMODULE_ERR;
    }

    return incrGenericCommand(ctx, argv, argc, (double) incr);
}

/**
 * JSON.INCRBYFLOAT <key> [path] <value>
 * value range: double
 * Increments the value stored under `path` by `value`.
 * `path` must exist path and must be a number value.
 * Reply: String, specifically the resulting JSON number value
 */
int TairDocIncrByFloat_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 3) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    double incr = 0.0;
    if (REDISMODULE_OK != RedisModule_StringToDouble(argc == 4 ? argv[3] : argv[2], &incr)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_VALUE_OUTOF_RANGE);
        return REDISMODULE_ERR;
    }

    return incrGenericCommand(ctx, argv, argc, incr);
}

/**
 * JSON.STRAPPEND <key> [path] <json-string>
 * Append the `json-string` value(s) the string at `path`.
 * `path` defaults to root if not provided.
 * Reply: Integer, -1 : key not exists, other: specifically the string's new length.
 */
int TairDocStrAppend_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 3) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int type;
    RedisModuleString *appendArg = NULL;
    char *pointer = NULL, *appendStr = NULL;
    cJSON *root = NULL, *pnode = NULL;
    size_t oldlen, appendlen, newlen;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 4 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsString(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_STRING);
        return REDISMODULE_ERR;
    }

    appendArg = argc == 4 ? argv[3] : argv[2];
    oldlen = strlen(pnode->valuestring);
    appendStr = (char *) RedisModule_StringPtrLen(appendArg, &appendlen);
    if (appendlen == 0) {
        RedisModule_ReplyWithLongLong(ctx, (long) oldlen);
    } else {
        newlen = oldlen + appendlen;
        pnode->valuestring = RedisModule_Realloc(pnode->valuestring, newlen + 1);
        memcpy(pnode->valuestring + oldlen, appendStr, appendlen);
        pnode->valuestring[newlen] = '\0';
        RedisModule_ReplyWithLongLong(ctx, (long) newlen);
    }

    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;
}

/**
 * JSON.STRLEN <key> [path]
 * Report the length of the JSON value at `path` in `key`.
 *
 * `path` defaults to root if not provided. If the `key` or `path` do not exist, null is returned.
 *
 * Reply: Integer, specifically the length of the value.
 */
int TairDocStrLen_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 2) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int type = 0;
    char *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 3 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsString(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_STRING);
        return REDISMODULE_ERR;
    }

    RedisModule_ReplyWithLongLong(ctx, (long) strlen(pnode->valuestring));
    return REDISMODULE_OK;
}

/**
 * JSON.ARRPUSH <key> <path> <json> [<json> ...]
 * Append the `json` value(s) into the array at `path` after the last element in it.
 * Reply: Integer, specifically the array's new size
 */
int TairDocArrPush_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 4) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int i, type;
    RedisModuleString *jerr = NULL;
    char *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL, *node = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = (char *) RedisModule_StringPtrLen(argv[2], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsArray(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_ARRAY);
        return REDISMODULE_ERR;
    }

    for (i = 4; i <= argc; ++i) {
        if (REDISMODULE_OK != createNodeFromJson(&node, RedisModule_StringPtrLen(argv[i - 1], NULL), &jerr)) {
            // jerr will be free in addReplyErrorSds
            RedisModule_ReplyWithError(ctx, RedisModule_StringPtrLen(jerr, NULL));
            RedisModule_FreeString(NULL, jerr);
            goto error;
        }

        cJSON_AddItemToArray(pnode, node);
    }

    RedisModule_ReplyWithLongLong(ctx, cJSON_GetArraySize(pnode));
    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;

    error:
    if (node) cJSON_Delete(node);
    return REDISMODULE_ERR;
}

/**
 * JSON.ARRPOP <key> <path> [index]
 * Remove and return element from the index in the array.
 *
 * `path` the array pointer. `index` is the position in the array to start
 * popping from (defaults to -1, meaning the last element). Out of range indices are rounded to
 * their respective array ends. Popping an empty array yields null.
 *
 * Reply: Bulk String, specifically the popped JSON value.
 */
int TairDocArrPop_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 3) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int type = 0;
    char *pointer = NULL;
    long long index, arrlen;
    cJSON *root = NULL, *pnode = NULL, *node = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_NO_SUCKKEY_ERROR);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = (char *) RedisModule_StringPtrLen(argv[2], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsArray(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_ARRAY);
        return REDISMODULE_ERR;
    }

    index = -1;
    arrlen = cJSON_GetArraySize(pnode);
    if (argc > 3 && RedisModule_StringToLongLong(argv[3], &index) != REDISMODULE_OK) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_VALUE_OUTOF_RANGE);
        return REDISMODULE_ERR;
    }

    if (index < 0) index = index + arrlen;
    if (index < 0 || index >= arrlen) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_ARRAY_OUTFLOW);
        return REDISMODULE_ERR;
    }

    node = cJSON_DetachItemFromArray(pnode, (int) index);
    if (node != NULL && jsonNodeType(node->type) != NULL) {
        char *print = cJSON_PrintUnformatted(node);
        RedisModule_ReplyWithStringBuffer(ctx, print, strlen(print));
        RedisModule_Free(print);
        cJSON_Delete(node);

        if (!root->next && !root->prev && !root->child) {
            RedisModule_DeleteKey(key);
        }
        RedisModule_ReplicateVerbatim(ctx);
    } else {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_JSON_TYPE_ERROR);
        RedisModule_Log(ctx, "warning", "%s", TAIRDOC_ERROR_JSON_TYPE_ERROR);
        return REDISMODULE_ERR;
    }

    return REDISMODULE_OK;
}

/**
 * JSON.ARRINSERT <key> <path> <index> <json> [<json> ...]
 * Insert the `json` value(s) into the array at `path` before the `index` (shifts to the right).
 *
 * The index must be in the array's range. Inserting at `index` 0 prepends to the array.
 * Negative index values are interpreted as starting from the end.
 *
 * Reply: Integer, specifically the array's new size
 */
int TairDocArrInsert_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 5) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int i, type;
    RedisModuleString *jerr = NULL;
    char *pointer = NULL;
    long long index, arrlen;
    cJSON *root = NULL, *pnode = NULL, *node = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = (char *) RedisModule_StringPtrLen(argv[2], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsArray(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_ARRAY);
        return REDISMODULE_ERR;
    }

    index = -1;
    arrlen = cJSON_GetArraySize(pnode);
    if (RedisModule_StringToLongLong(argv[3], &index) != REDISMODULE_OK) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_VALUE_OUTOF_RANGE);
        return REDISMODULE_ERR;
    }

    if (index < 0) index = index + arrlen;
    if (index < 0 || index > arrlen) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_ARRAY_OUTFLOW);
        return REDISMODULE_ERR;
    }

    for (i = 5; i <= argc; ++i) {
        if (REDISMODULE_OK != createNodeFromJson(&node, RedisModule_StringPtrLen(argv[i - 1], NULL), &jerr)) {
            RedisModule_ReplyWithError(ctx, RedisModule_StringPtrLen(jerr, NULL));
            RedisModule_FreeString(NULL, jerr);
            goto error;
        }

        cJSON_InsertItemInArray(pnode, (int) index, node);
        index++;
    }

    RedisModule_ReplyWithLongLong(ctx, cJSON_GetArraySize(pnode));
    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;

    error:
    if (node) cJSON_Delete(node);
    return REDISMODULE_ERR;
}

/**
 * JSON.ARRLEN <key> [path]
 * Report the length of the array at `path` in `key`.
 *
 * `path` defaults to root if not provided. If the `key` or `path` do not exist, null is returned.
 *
 * Reply: Integer, specifically the length of the array.
 */
int TairDocArrLen_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 2) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    char *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ);
    int type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = argc == 3 ? (char *) RedisModule_StringPtrLen(argv[2], NULL) : "";
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsArray(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_ARRAY);
        return REDISMODULE_ERR;
    }

    RedisModule_ReplyWithLongLong(ctx, cJSON_GetArraySize(pnode));
    return REDISMODULE_OK;
}

/**
 * JSON.ARRTRIM <key> <path> <start> <stop>
 * Trim an array so that it contains only the specified inclusive range of elements.
 *
 * Reply: Integer, specifically the array's new size.
 */
int TairDocArrTrim_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 5) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    char *pointer = NULL;
    long long i, start, stop, arrlen, index;
    cJSON *root = NULL, *pnode = NULL;

    RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[1], REDISMODULE_READ | REDISMODULE_WRITE);
    int type = RedisModule_KeyType(key);
    if (REDISMODULE_KEYTYPE_EMPTY == type) {
        RedisModule_ReplyWithLongLong(ctx, -1);
        return REDISMODULE_ERR;
    } else {
        if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
            RedisModule_ReplyWithError(ctx, REDISMODULE_ERRORMSG_WRONGTYPE);
            return REDISMODULE_ERR;
        }
        root = RedisModule_ModuleTypeGetValue(key);
    }

    pointer = (char *) RedisModule_StringPtrLen(argv[2], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
    if (pnode == NULL || !cJSON_IsArray(pnode)) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_NOT_ARRAY);
        return REDISMODULE_ERR;
    }

    if (RedisModule_StringToLongLong(argv[3], &start) != REDISMODULE_OK ||
        RedisModule_StringToLongLong(argv[4], &stop) != REDISMODULE_OK) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_VALUE_OUTOF_RANGE);
        return REDISMODULE_ERR;
    }

    arrlen = cJSON_GetArraySize(pnode);
    if (start < 0 || stop < 0 || start > stop || start >= arrlen || stop >= arrlen) {
        RedisModule_ReplyWithError(ctx, TAIRDOC_ERROR_ARRAY_OUTFLOW);
        return REDISMODULE_ERR;
    }

    index = 0;
    for (i = index; i < start; ++i) {
        cJSON_DeleteItemFromArray(pnode, (int) index);
    }

    arrlen -= start;
    index = stop - start + 1;
    for (i = index; i < arrlen; ++i) {
        cJSON_DeleteItemFromArray(pnode, (int) index);
    }

    if (!root->next && !root->prev && !root->child) {
        RedisModule_DeleteKey(key);
    }

    RedisModule_ReplyWithLongLong(ctx, cJSON_GetArraySize(pnode));
    RedisModule_ReplicateVerbatim(ctx);
    return REDISMODULE_OK;
}

/**
 * JSON.MGET <key> [<key> ...] <path>
 * Returns the values at `path` from multiple `key`s. Non-existing keys and non-existing paths
 * are reported as null.
 * Reply: Array of Bulk Strings, specifically the JSON serialization of
 * the value at each key's path.
 */
int TairDocMget_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc < 3) {
        RedisModule_WrongArity(ctx);
        return REDISMODULE_ERR;
    }
    RedisModule_AutoMemory(ctx);

    int j;
    char *print = NULL;
    char *pointer = NULL;
    cJSON *root = NULL, *pnode = NULL;

    pointer = (char *) RedisModule_StringPtrLen(argv[argc - 1], NULL);
    RedisModuleString *rpointer = NULL;
    PATH_TO_POINTER(ctx, pointer, rpointer)

    RedisModule_ReplyWithArray(ctx, argc - 2);
    for (j = 1; j < argc - 1; ++j) {
        RedisModuleKey *key = RedisModule_OpenKey(ctx, argv[j], REDISMODULE_READ);
        int type = RedisModule_KeyType(key);
        if (REDISMODULE_KEYTYPE_EMPTY == type) {
            RedisModule_ReplyWithNull(ctx);
        } else {
            if (RedisModule_ModuleTypeGetType(key) != TairDocType) {
                RedisModule_ReplyWithNull(ctx);
            } else {
                root = RedisModule_ModuleTypeGetValue(key);
                pnode = cJSONUtils_GetPointerCaseSensitive(root, RedisModule_StringPtrLen(rpointer, NULL));
                if (pnode == NULL || jsonNodeType(pnode->type) == NULL) {
                    RedisModule_ReplyWithNull(ctx);
                    continue;
                }
                print = cJSON_PrintUnformatted(pnode);
                RedisModule_ReplyWithStringBuffer(ctx, print, strlen(print));
                RedisModule_Free(print);
            }
        }
    }
    return REDISMODULE_OK;
}

/* ========================== TairDoc type methods ======================= */

void *TairDocTypeRdbLoad(RedisModuleIO *rdb, int encver) {
    if (encver != TAIRDOC_ENC_VER) {
        return NULL;
    }

    cJSON *root = NULL;
    char *json = NULL;
    size_t len = 0;

    json = RedisModule_LoadStringBuffer(rdb, &len);
    if (json != NULL && len != 0) {
        root = cJSON_Parse((const char *) json);
        RedisModule_Free(json);
        return root;
    } else {
        RedisModule_LogIOError(
                rdb, "warning",
                "TairDocTypeRdbLoad load json return NULL, TAIRDOC_ENC_VER: %d", TAIRDOC_ENC_VER);
    }
    return NULL;
}

void TairDocTypeRdbSave(RedisModuleIO *rdb, void *value) {
    cJSON *root = value;
    char *serialize = cJSON_PrintUnformatted(root);
    if (serialize != NULL) {
        RedisModule_SaveStringBuffer(rdb, serialize, strlen(serialize) + 1);
        RedisModule_Free(serialize);
    } else {
        RedisModule_LogIOError(
                rdb, "warning",
                "TairDocTypeRdbSave serialize json return NULL, TAIRDOC_ENC_VER: %d", TAIRDOC_ENC_VER);
    }
}

void TairDocTypeAofRewrite(RedisModuleIO *aof, RedisModuleString *key, void *value) {
    cJSON *root = value;
    if (root != NULL) {
        char *serialize = cJSON_PrintUnformatted(root);
        RedisModule_EmitAOF(aof, "JSON.SET", "scc", key, "", serialize);
        RedisModule_Free(serialize);
    }
}

size_t TairDocTypeMemUsage(const void *value) {
    REDISMODULE_NOT_USED(value);
    return 0;
}

void TairDocTypeFree(void *value) {
    cJSON *root = value;
    cJSON_Delete(root);
}

void TairDocTypeDigest(RedisModuleDigest *md, void *value) {
    REDISMODULE_NOT_USED(md);
    REDISMODULE_NOT_USED(value);
}

static size_t TairDocTypeFreeEffort(RedisModuleString * key, const void *value) {
    REDISMODULE_NOT_USED(key);
    REDISMODULE_NOT_USED(value);
    return 0;
}

int Module_CreateCommands(RedisModuleCtx *ctx) {

#define CREATE_CMD(name, tgt, attr)                                                                \
    do {                                                                                           \
        if (RedisModule_CreateCommand(ctx, name, tgt, attr, 1, 1, 1) != REDISMODULE_OK) {          \
            return REDISMODULE_ERR;                                                                \
        }                                                                                          \
    } while (0);
#define CREATE_WRCMD(name, tgt) CREATE_CMD(name, tgt, "write deny-oom")
#define CREATE_ROCMD(name, tgt) CREATE_CMD(name, tgt, "readonly fast")

    CREATE_WRCMD("json.set", TairDocSet_RedisCommand)
    CREATE_ROCMD("json.get", TairDocGet_RedisCommand)
    CREATE_ROCMD("json.type", TairDocType_RedisCommand)
    CREATE_WRCMD("json.del", TairDocDel_RedisCommand)
    CREATE_WRCMD("json.forget", TairDocDel_RedisCommand)
    CREATE_WRCMD("json.incrby", TairDocIncrBy_RedisCommand)
    CREATE_WRCMD("json.incrbyfloat", TairDocIncrByFloat_RedisCommand)
    CREATE_WRCMD("json.numincrby", TairDocIncrByFloat_RedisCommand)
    CREATE_ROCMD("json.strlen", TairDocStrLen_RedisCommand)
    CREATE_WRCMD("json.strappend", TairDocStrAppend_RedisCommand)
    CREATE_ROCMD("json.arrlen", TairDocArrLen_RedisCommand)
    CREATE_WRCMD("json.arrinsert", TairDocArrInsert_RedisCommand)
    CREATE_WRCMD("json.arrpush", TairDocArrPush_RedisCommand)
    CREATE_WRCMD("json.arrappend", TairDocArrPush_RedisCommand)
    CREATE_WRCMD("json.arrpop", TairDocArrPop_RedisCommand)
    CREATE_WRCMD("json.arrtrim", TairDocArrTrim_RedisCommand)

    // JSON.MGET is a multi-key command
    if (RedisModule_CreateCommand(ctx, "json.mget", TairDocMget_RedisCommand, "readonly",
                                   1, -2, 1) != REDISMODULE_OK) {
        return REDISMODULE_ERR;
    }
    return REDISMODULE_OK;
}


/* This function must be present on each Redis module. It is used in order to
 * register the commands into the Redis server. */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    if (RedisModule_Init(ctx, "tair-json", 1, REDISMODULE_APIVER_1)
        == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    RedisModuleTypeMethods tm = {
            .version = REDISMODULE_TYPE_METHOD_VERSION,
            .rdb_load = TairDocTypeRdbLoad,
            .rdb_save = TairDocTypeRdbSave,
            .aof_rewrite = TairDocTypeAofRewrite,
            .mem_usage = TairDocTypeMemUsage,
            .free = TairDocTypeFree,
            .digest = TairDocTypeDigest,
    };
    TairDocType = RedisModule_CreateDataType(ctx, "tair-json", 0, &tm);
    if (TairDocType == NULL) return REDISMODULE_ERR;

    // Init cJSON_Hooks
    cJSON_Hooks TairDoc_hooks = {
            RedisModule_Alloc,
            RedisModule_Free,
            RedisModule_Realloc,
    };
    cJSON_InitHooks(&TairDoc_hooks);

    // Create Commands
    if (REDISMODULE_ERR == Module_CreateCommands(ctx)) return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
