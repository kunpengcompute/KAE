#include <errno.h>
#include <dirent.h>
#include "acc_utils.h"
#include "rde.h"
#include "acc.h"
#include "zip.h"

/* Version number maintenance rule:
 * the third corresponds to the B version, and the fourth is the
 * corresponding modification in the B version.
 */
#define ACC_WD_VER "1.8.19.0"

#define SYS_CLASS_UACCE_DIR "/sys/class/uacce"
#define DEVICE_RESET_PATH "/device/reset"

#define ATTR_ISOLATE_PATH     "/attrs/isolate"
#define ACC_ALG_ALL (-1)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct file_path_tbl {
    ACC_ATTR_CONFIG_E config_type;
    char *path;
};

struct alg_module_tbl {
    ACC_ALG_E alg_type;
    char      *module;
};

struct file_path_tbl g_acc_file_path_tbl[] = {
    {ACC_ATTR_ISOLATION_STRATEGY,     "/attrs/isolate_strategy"}
};

struct alg_module_tbl g_acc_alg_module_tbl[] = {
    {ACC_ALG_ALL,               "hisi"},
    {ACC_ALG_ZLIB,              "zip"},
    {ACC_ALG_GZIP,              "zip"},
    {ACC_ALG_AES128,            "sec"},
    {ACC_ALG_AES192,            "sec"},
    {ACC_ALG_AES256,            "sec"},
    {ACC_ALG_SM4128,            "sec"},
    {ACC_ALG_DES,               "sec"},
    {ACC_ALG_3DES,              "sec"},
    {ACC_ALG_SHA1,              "sec"},
    {ACC_ALG_SHA_256,           "sec"},
    {ACC_ALG_MD5,               "sec"},
    {ACC_ALG_SHA_224,           "sec"},
    {ACC_ALG_SHA_384,           "sec"},
    {ACC_ALG_SHA_512,           "sec"},
    {ACC_ALG_SHA_512_224,       "sec"},
    {ACC_ALG_SHA_512_256,       "sec"},
    {ACC_ALG_HMAC_SHA1,         "sec"},
    {ACC_ALG_HMAC_SHA_256,      "sec"},
    {ACC_ALG_HMAC_MD5,          "sec"},
    {ACC_ALG_HMAC_SHA_224,      "sec"},
    {ACC_ALG_HMAC_SHA_384,      "sec"},
    {ACC_ALG_HMAC_SHA_512,      "sec"},
    {ACC_ALG_HMAC_SHA_512_224,  "sec"},
    {ACC_ALG_HMAC_SHA_512_256,  "sec"},
    {ACC_ALG_AES_XCBC,          "sec"},
    {ACC_ALG_AES_CMAC,          "sec"},
    {ACC_ALG_AES_GMAC,          "sec"},
    {ACC_ALG_SM3,               "sec"},
    {ACC_ALG_HMAC_SM3,          "sec"},
    {ACC_ALG_FLEXEC,            "rde"},
    {ACC_ALG_MPCC,              "rde"}
};

static int acc_read_file(const char *file_path, int *value)
{
    FILE *fp;
    int ret;

    fp = fopen(file_path, "r");
    if (fp == NULL) {
        ACC_LOG("open file %s failed!\n", file_path);
        return ACC_UNSUPPORTED;
    }

    ret = fscanf(fp, "%d", value);
    if (ret < 0) {
        fclose(fp);
        ACC_LOG("read file %s failed!\n", file_path);
        return ACC_RETRY;
    }
    fclose(fp);

    return ACC_SUCCESS;
}

static int acc_write_file(const char *file_path, int value)
{
    FILE *fp;
    int ret;

    fp = fopen(file_path, "w");
    if (fp == NULL) {
        ACC_LOG("open file %s failed!\n", file_path);
        return ACC_UNSUPPORTED;
    }

    /* fprintf write content only to the buffer, so you need to determine
       whether to write to the file based on the return of fflush() */
    ret = fprintf(fp, "%d", value);
    if (ret < 0) {
        ACC_LOG("write to file %s failed!\n", file_path);
        goto err_with_write;
    }

    ret = fflush(fp);
    if (ret < 0) {
        ACC_LOG("write to file %s failed!\n", file_path);
        goto err_with_write;
    }

    fclose(fp);
    return ACC_SUCCESS;

err_with_write:
    fclose(fp);
    return ACC_UNSUPPORTED;
}

static char *acc_get_module_by_alg(int alg_type)
{
    int idx;

    for (idx = 0; idx < ARRAY_SIZE(g_acc_alg_module_tbl); idx++) {
        if (alg_type == g_acc_alg_module_tbl[idx].alg_type) {
            return g_acc_alg_module_tbl[idx].module;
        }
    }
    return NULL;
}

static int acc_check_param(int config_type, const char *module,
    const int *value)
{
    if (value == NULL) {
        ACC_LOG("parameter address error.\n");
        return ACC_INVALID_PARAM;
    }

    if (module == NULL)
        return ACC_UNSUPPORTED;

    if (config_type < 0 || config_type >= ACC_ATTR_BUTT)
        return ACC_INVALID_PARAM;

    return ACC_SUCCESS;
}

static int acc_check_isolate(const char *name)
{
    char isolate_path[PATH_STR_SIZE];
    int isolate_sign;
    int ret;

    ret = snprintf(isolate_path, PATH_STR_SIZE, "%s/%s%s",
    SYS_CLASS_UACCE_DIR, name, ATTR_ISOLATE_PATH);
    if (ret < 0) {
        ACC_LOG("get %s/%s%s failed!\n", SYS_CLASS_UACCE_DIR, name,
            ATTR_ISOLATE_PATH);
        return ACC_UNSUPPORTED;
    }

    ret = acc_read_file(isolate_path, &isolate_sign);
    if (ret < 0)
        return ret;
    if (isolate_sign == 1)
        return ACC_NO_ENGINE_AVAILABLE;

    return ACC_SUCCESS;
}

static int acc_oprerate_get_config(const char *name, int config_type,
    int *value, int *data_consist)
{
    char file_path[PATH_STR_SIZE];
    char *attr_path = NULL;
    int ret;

    attr_path = g_acc_file_path_tbl[config_type].path;
    ret = snprintf(file_path, PATH_STR_SIZE, "%s/%s%s",
        SYS_CLASS_UACCE_DIR, name, attr_path);
    if (ret < 0) {
        ACC_LOG("get %s/%s%s failed!\n", SYS_CLASS_UACCE_DIR, name, attr_path);
        return ACC_UNSUPPORTED;
    }

    ret = acc_read_file(file_path, value);
    if (ret < 0)
        return ret;

    if (*data_consist == -1)
        *data_consist = *value;
    else if (*data_consist != *value) {
        WD_ERR("find inconsistent data: (%d) (%d).\n", *data_consist, *value);
        return ACC_UNSUPPORTED;
    }

    return ACC_SUCCESS;
}

static int acc_oprerate_set_config(const char *name, int config_type, int value)
{
    char file_path[PATH_STR_SIZE];
    char *attr_path;
    int ret;

    attr_path = g_acc_file_path_tbl[config_type].path;
    ret = snprintf(file_path, PATH_STR_SIZE, "%s/%s%s",
        SYS_CLASS_UACCE_DIR, name, attr_path);
    if (ret < 0) {
        ACC_LOG("get %s/%s%s failed!\n", SYS_CLASS_UACCE_DIR, name, attr_path);
        return ACC_UNSUPPORTED;
    }

    ret = acc_write_file(file_path, value);
    if (ret < 0)
        return ret;

    return ACC_SUCCESS;
}

int acc_transform_err_code(int value)
{
	int ret;

	switch (value) {
	case WD_SUCCESS:
		ret = ACC_SUCCESS;
		break;
	case -WD_EIO:
		ret = ACC_FATAL_INSTANCE;
		break;
	case -WD_EAGAIN:
		ret = ACC_RETRY;
		break;
	case -WD_EBUSY:
		ret = ACC_BUSY_INSTANCE;
		break;
	case -WD_ENODEV:
		ret = ACC_UNSUPPORTED;
		break;
	case -WD_ETIMEDOUT:
		ret = ACC_TMOUT;
		break;
	case -WD_HW_EACCESS:
		ret = ACC_FATAL_ENGINE;
		break;
	case -WD_EINVAL:
	case -WD_ADDR_ERR:
	case -WD_SGL_ERR:
	case -WD_OUT_EPARA:
	case -WD_IN_EPARA:
		ret = ACC_INVALID_PARAM;
		break;
	default:
		ret = value;
		break;
	}

	return ret;
}

/**
 *
 * @brief initialization before you call the other api.
 *
 * @param [in] ctx is the context which manage the instance.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Be sure you will call this function first.
 *
 */
int acc_init(struct acc_ctx *ctx)
{
	if (!ctx) {
		WD_ERR("acc_init parameter error.\n");
		return ACC_INVALID_PARAM;
	}

	switch (ctx->alg_type) {
	case ACC_ALG_GZIP:
	case ACC_ALG_ZLIB:
		return acc_zip_init(ctx);
	case ACC_ALG_FLEXEC:
	case ACC_ALG_MPCC:
		return acc_rde_init(ctx);
	default:
		WD_ERR("unknown alg type %d.\n", ctx->alg_type);
		return ACC_INVALID_PARAM;
	}
}

/**
 *
 * @brief send and receive tasks synchronously.
 *
 * @param [in] ctx is the context which manage the instance.
 * @param [in] dst is the destination address.
 * @param [in] dst_len is the destination total length.
 * @param [in] src is the source address.
 * @param [in] src_len is the source total length.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_update(struct acc_ctx *ctx,
        void *dst, size_t dst_len, const void *src, size_t src_len)
{
    return 0;
}

/**
 *
 * @brief release resource that alloced by acc_init().
 *
 * @param [in] ctx is the context which manage the instance.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_clear(struct acc_ctx *ctx)
{
	if (!ctx) {
		WD_ERR("acc_clear parameter error.\n");
		return ACC_INVALID_PARAM;
	}

	switch (ctx->alg_type) {
	case ACC_ALG_GZIP:
	case ACC_ALG_ZLIB:
		return acc_zip_clear(ctx);
	case ACC_ALG_FLEXEC:
	case ACC_ALG_MPCC:
		return acc_rde_clear(ctx);
	default:
		WD_ERR("unknown alg type %d.\n", ctx->alg_type);
		return ACC_INVALID_PARAM;
	}
}

/**
 *
 * @brief 设置T10 CRC seed.
 *
 * @param [in] seed T10 CRC seed.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_set_pi_crc_seed(uint16_t seed)
{
    return 0;
}

/**
 *
 * @brief 设置PRP的页面大??
 *
 * @param [in] page_size typical values: 4096 bytes, 8192 bytes.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_set_prp_mem_page_size(uint32_t page_size)
{
    return 0;
}

/**
 *
 * @brief 设置SGE相对SGL的offset.
 *
 * @param [in] offset typical values: 32 bytes, 64 bytes.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_set_sge_offset_from_sgl(uint32_t offset)
{
    return 0;
}

/**
 *
 * @brief 设置Comp Head Size.
 *
 * @param [in]
 * @param [in] size typical values: 64 bytes, 128 bytes.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 *
 */
int acc_set_comp_head_size(uint32_t size)
{
    return 0;
}

int acc_poll(struct acc_ctx *ctx, int num)
{
	if (!ctx || num < 0) {
		WD_ERR("acc_poll parameter error.\n");
		return ACC_INVALID_PARAM;
	}

	switch (ctx->alg_type) {
	case ACC_ALG_GZIP:
	case ACC_ALG_ZLIB:
		return acc_zip_poll(ctx, num, NULL);
	case ACC_ALG_FLEXEC:
	case ACC_ALG_MPCC:
		return acc_rde_poll(ctx, num, NULL);
	default:
		WD_ERR("unknown alg type %d.\n", ctx->alg_type);
		return ACC_INVALID_PARAM;
	}
}

int acc_poll_v2(struct acc_ctx *ctx, int num, int *remainder)
{
	if (!ctx || num < 0) {
		WD_ERR("acc_poll_v2 parameter error.\n");
		return ACC_INVALID_PARAM;
	}

	switch (ctx->alg_type) {
	case ACC_ALG_GZIP:
	case ACC_ALG_ZLIB:
		return acc_zip_poll(ctx, num, remainder);
	case ACC_ALG_FLEXEC:
	case ACC_ALG_MPCC:
		return acc_rde_poll(ctx, num, remainder);
	default:
		WD_ERR("unknown alg type %d.\n", ctx->alg_type);
		return ACC_INVALID_PARAM;
	}
}

int acc_setup_log(acc_log log_func)
{
    if (!log_func) {
        return -ACC_INVALID_PARAM;
    }

    dbg_log = log_func;

    return ACC_SUCCESS;
}

int acc_dev_flr_reset(struct acc_ctx *ctx)
{
    struct acc_inner *inner;
    int ret;
    const char *reset_flag = "1";
    const int dev_offset = 4; /* "/dev" */
    char reset_file[PATH_STR_SIZE];
    int fd = -1;
    struct wd_queue *q;

    if (!ctx) {
        WD_ERR("ctx error.\n");
        return ACC_INVALID_PARAM;
    }

    inner = ctx->inner;
    if (!inner) {
        WD_ERR("inner error.\n");
        return ACC_INVALID_PARAM;
    }

    q = inner->q;
    ret = snprintf(reset_file, PATH_STR_SIZE, "%s%s%s",
        SYS_CLASS_UACCE_DIR, q->dev_path + dev_offset, DEVICE_RESET_PATH);
    if (ret < 0) {
        ACC_LOG("get %s%s%s failed!\n", SYS_CLASS_UACCE_DIR,
            q->dev_path + dev_offset, DEVICE_RESET_PATH);
        return ACC_UNSUPPORTED;
    }

    fd = open(reset_file, O_WRONLY, 0);
    if (fd < 0) {
        ACC_LOG("open %s fail!\n", reset_file);
        return ACC_UNSUPPORTED;
    }

    ret = write(fd, reset_flag, 1);
    if (ret <= 0) {
        close(fd);
        return ACC_UNSUPPORTED;
    }

    close(fd);

    return ACC_SUCCESS;
}

int acc_get_dev_idle_state(int alg_type, int *state)
{
    int ret = 0;

    if (!state)
        return ACC_INVALID_PARAM;

    switch (alg_type) {
    case ACC_ALG_ZLIB:
    case ACC_ALG_GZIP:
        ret = acc_zip_get_dev_idle_state(state);
        break;
    default:
        ACC_LOG("unknown alg type %d.\n", alg_type);
        return ACC_INVALID_PARAM;
    }

    if (ret) {
        *state = 0;
    }

    return ACC_SUCCESS;
}

int acc_get_available_dev_num(int alg_type, int *num)
{
    if (!num)
        return ACC_INVALID_PARAM;

    switch (alg_type) {
    case ACC_ALG_ZLIB:
        *num = wd_get_available_dev_num("zlib");
        break;
    case ACC_ALG_GZIP:
        *num = wd_get_available_dev_num("gzip");
        break;
    default:
        ACC_LOG("unknown alg type %d.\n", alg_type);
        return ACC_INVALID_PARAM;
    }

    return ACC_SUCCESS;
}

/**
 *
 * @brief get config value according to algorithm.
 *
 * @param [in] alg_type is the algorithm type ACC_ALG_E.
 * ACC_ALG_ZLIB/ACC_ALG_GZIP correspond compression engine.
 * ACC_ALG_AES128 ~ ACC_ALG_HMAC_SM3 correspond cryptographic engine.
 * @param [in] config_type is the supported config enum ACC_ATTR_CONFIG_E.
 * @param [out] value is the configuration's content.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * This interface does not support concurrent use. Do not support VF.
 *
 */
int acc_get_config(int alg_type, int config_type, int *value)
{
    DIR *sys_uacce_dir = NULL;
    struct dirent *device = NULL;
    char *module = NULL;
    char *name = NULL;
    int data_consist = -1;
    int ret;

    module = acc_get_module_by_alg(alg_type);
    ret = acc_check_param(config_type, module, value);
    if (ret < 0) {
        ACC_LOG("parameter error, alg_type (%d), config_type (%d).\n",
            alg_type, config_type);
        return ret;
    }

    sys_uacce_dir = opendir(SYS_CLASS_UACCE_DIR);
    if (!sys_uacce_dir) {
        ACC_LOG("opendir uacce failed!\n");
        return ACC_UNSUPPORTED;
    }

    /* Use get_config_status to determine whether to find the appropriate file:
     * find: ACC_SUCCESS
     * not find: ACC_NO_ENGINE_AVAILABLE
     */
    while (true) {
        device = readdir(sys_uacce_dir);
        if (!device)
            break;

        name = device->d_name;
        if (strstr(name, module) == NULL)
            continue;

        ret = acc_check_isolate(name);
        if (ret == ACC_NO_ENGINE_AVAILABLE)
            continue;

        if (ret < 0)
            break;

        ret = acc_oprerate_get_config(name, config_type, value, &data_consist);
        if (ret < 0)
            break;
    }

    if (sys_uacce_dir)
        closedir(sys_uacce_dir);

    return ret;
}

/**
 *
 * @brief set config value according to algorithm.
 *
 * @param [in] alg_type is the algorithm type ACC_ALG_E.
 * ACC_ALG_ZLIB/ACC_ALG_GZIP correspond compression engine.
 * ACC_ALG_AES128 ~ ACC_ALG_HMAC_SM3 correspond cryptographic engine.
 * @param [in] config_type is the supported config enum ACC_ATTR_CONFIG_E.
 * @param [in] value is the content that needs to be configured.
 * Range is 0 ~ 65535.
 * @retval 0 is success, else is a negative number that is error code.
 *
 * @note
 * Cannot use set configuration interface when using business, will return busy.
 * This interface does not support concurrent use. Do not support VF.
 *
 */
int acc_set_config(int alg_type, int config_type, int value)
{
    DIR *sys_uacce_dir = NULL;
    struct dirent *device = NULL;
    char *module = NULL;
    char *name = NULL;
    int ret;

    ACC_LOG("ACC wd version:%s!\n", ACC_WD_VER);

    module = acc_get_module_by_alg(alg_type);
    ret = acc_check_param(config_type, module, &value);
    if (ret < 0)
        return ret;

    sys_uacce_dir = opendir(SYS_CLASS_UACCE_DIR);
    if (!sys_uacce_dir) {
        ACC_LOG("opendir uacce failed!\n");
        return ACC_UNSUPPORTED;
    }

    /* Use ret to determine whether to find the appropriate file:
     * find: ACC_SUCCESS
     * not find: ACC_NO_ENGINE_AVAILABLE
     */
    ret = ACC_NO_ENGINE_AVAILABLE;
    while (true) {
        device = readdir(sys_uacce_dir);
        if (!device)
            break;

        name = device->d_name;
        if (strstr(name, module) == NULL)
            continue;

        ret = acc_oprerate_set_config(name, config_type, value);
        if (ret < 0)
            break;
    }

    if (sys_uacce_dir)
        closedir(sys_uacce_dir);

    ACC_LOG("ACC set config finish. ret:%d\n", ret);

    return ret;
}

