#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "acc_utils.h"

acc_log dbg_log = (acc_log)printf;

void *acc_alloc_sgl(uint32_t dlen, uint32_t sge_size, uint32_t sgl_max_entry)
{
    int i;
    uint32_t sge_len = sge_size;
    uint32_t len = 0;
    struct sgl_hw *sgl, *sgl_cur, *sgl_next;
    uint32_t entry_sum_in_sgl;
    uint32_t entry_num_in_sgl;
    uint32_t entry_sum_in_chain = 0;

    sgl = calloc(1, sizeof(struct sgl_hw) + sgl_max_entry * sizeof(struct sgl_entry_hw));
    if (!sgl)
        return NULL;

    sgl_next = sgl;

    while (len < dlen) {
        sgl_cur = sgl_next;
        entry_num_in_sgl = 0;
        entry_sum_in_sgl = 0;

        for (i = 0; i < sgl_max_entry && len < dlen; i++) {
            /* In case the length exceed the buffer we've allocated. */
            if (len + sge_len > dlen)
                sge_len = dlen - len;

            sgl_cur->entrys[i].buf = malloc(sge_len);
            if (!sgl_cur->entrys[i].buf) {
                ACC_LOG("alloc sgl_cur->entrys[i].buf fail.\n");
                goto exit;
            }

            sgl_cur->entrys[i].len = sge_len;
            len += sge_len;

            entry_num_in_sgl++;
            entry_sum_in_sgl++;
            entry_sum_in_chain++;
        }

        sgl_cur->entry_num_in_sgl = entry_num_in_sgl;
        sgl_cur->entry_sum_in_sgl = entry_sum_in_sgl;

        if (len >= dlen)
            break;

        sgl_next = calloc(1, sizeof(struct sgl_hw));
        if (!sgl_next) {
            ACC_LOG("alloc sgl_next fail.\n");
            goto exit;
        }

        sgl_cur->next = sgl_next;
    }

    sgl->entry_sum_in_chain = entry_sum_in_chain;

    return sgl;

exit:
    acc_free_sgl(sgl);
    return NULL;
}

void acc_free_sgl(struct sgl_hw *sgl)
{
	struct sgl_hw *sgl_cur, *sgl_next;
	int i;

	if (!sgl)
		return;

	for (sgl_cur = sgl; sgl_cur != NULL;) {
		/* free the buffer */
		for (i = 0; i < sgl_cur->entry_sum_in_sgl; i++) {
		       if (sgl_cur->entrys[i].buf)
                        free(sgl_cur->entrys[i].buf);
		}

		sgl_next = sgl_cur->next;
		free(sgl_cur);
		sgl_cur = sgl_next;
	}
}

int acc_sgl_to_buf(struct sgl_hw *sgl, void *buf, size_t len, size_t offset)
{
	int off = 0, length = 0, sge = 0, i = 0, cp_len = 0, left_len = 0;
	struct sgl_hw *sgl_cur = NULL;

    if (sgl == NULL) {
        return -EINVAL;
    }

	/* find the right sge to read */
	for (off = offset, sgl_cur = sgl; off >= sgl_cur->entrys[sge].len;) {
            if (!sgl_cur) {
                ACC_LOG("[%s][%d]sgl is null.\n", __FUNCTION__, __LINE__);
                return -1;
            }

		for (sge = 0; off > 0 && sge < sgl_cur->entry_sum_in_sgl &&
			off >= sgl_cur->entrys[sge].len; sge++)
			off -= sgl_cur->entrys[sge].len;

		/* fix sge */
		if (sge >= sgl_cur->entry_sum_in_sgl && off > 0) {
			sge = 0;
			sgl_cur = sgl_cur->next;
		}
	}

	/* copy data to sgl, start from sgl_cur, the sge, buffer off set is off */
	for (length = 0; NULL != sgl_cur && length < len;
		sgl_cur = sgl_cur->next) {
		for (i = sge, left_len = len - length;
			i < sgl_cur->entry_sum_in_sgl && length < len; i++) {
			left_len = len - length;
			if ((sgl_cur->entrys[i].len - off) >= left_len)
				cp_len = left_len;
			else
				cp_len = sgl_cur->entrys[i].len - off;

			memcpy(buf + length, sgl_cur->entrys[i].buf + off, cp_len);

			length += cp_len;
			off = 0;
		}
		sge = 0;
	}

	return 0;
}

int acc_buf_to_sgl(void *buf, struct sgl_hw *sgl, size_t len, size_t offset)
{
    struct sgl_hw *sgl_cur;
    size_t off;
    int length = 0;
    int sge = 0;
    int i = 0;
    int cp_len = 0;
    int left_len = 0;

    if (sgl == NULL) {
        return -EINVAL;
    }

    /* find the current sge to read */
    for (off = offset, sgl_cur = sgl;
        off >= sgl_cur->entrys[sge].len;) {
        if (!sgl_cur) {
            ACC_LOG("[%s][%d]sgl is null.\n", __FUNCTION__, __LINE__);
            return -1;
        }

        for (sge = 0; sge < sgl_cur->entry_sum_in_sgl &&
            off >= sgl_cur->entrys[sge].len; sge++) {
            off -= sgl_cur->entrys[sge].len;
        }

        /* fix sge */
        if (sge >= sgl_cur->entry_sum_in_sgl && off > 0) {
            sge = 0;
            sgl_cur = sgl_cur->next;
        }
    }

    /* copy data to sgl, start from sgl_cur, the sge, buffer off set is off */
    for (length = 0; sgl_cur != NULL && length < len;
        sgl_cur = sgl_cur->next) {
        for (i = sge; i < sgl_cur->entry_sum_in_sgl && length < len; i++) {
            left_len = len - length;
            if ((sgl_cur->entrys[i].len - off) >= left_len)
                cp_len = left_len;
            else
                cp_len = sgl_cur->entrys[i].len - off;

            memcpy(sgl_cur->entrys[i].buf + off, buf + length, cp_len);
            length += cp_len;
            off = 0;
        }

        sge = 0; // only the first copy to the off sge
    }

    return 0;
}



