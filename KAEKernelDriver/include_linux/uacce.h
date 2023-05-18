/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_UACCE_H
#define _LINUX_UACCE_H

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/iommu.h>
#include "../include_uapi_linux/uacce.h"

#define UACCE_NAME		"uacce"
#define UACCE_MAX_REGION	3
#define UACCE_MAX_NAME_SIZE	64
#define UACCE_MAX_ERR_THRESHOLD	65535

struct uacce_queue;
struct uacce_device;

struct uacce_err_isolate {
	u32 hw_err_isolate_hz;	/* user cfg freq which triggers isolation */
	atomic_t is_isolate;
};

struct uacce_dma_slice {
	void *kaddr;	/* kernel address for ss */
	dma_addr_t dma;	/* dma address, if created by dma api */
	u64 size;	/* Size of this dma slice */
	u32 total_num;	/* Total slices in this dma list */
};

/**
 * struct uacce_qfile_region - structure of queue file region
 * @type: type of the region
 */
struct uacce_qfile_region {
	enum uacce_qfrt type;
	unsigned long iova;	/* iova share between user and device space */
	unsigned long nr_pages;
	int prot;
	unsigned int flags;
	struct list_head qs;	/* qs sharing the same region, for ss */
	void *kaddr;		/* kernel address for dko */
	struct uacce_dma_slice *dma_list;
};

/**
 * struct uacce_ops - uacce device operations
 * @get_available_instances:  get available instances left of the device
 * @get_queue: get a queue from the device
 * @put_queue: free a queue to the device
 * @start_queue: make the queue start work after get_queue
 * @stop_queue: make the queue stop work before put_queue
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @ioctl: ioctl for user space users of the queue
 * @get_isolate_state: get the device state after set the isolate strategy
 * @isolate_err_threshold_write: stored the isolate error threshold to the device
 * @isolate_err_threshold_read: read the isolate error threshold value from the device
 * @reset: reset the WD device
 * @reset_queue: reset the queue
 */
struct uacce_ops {
	int (*get_available_instances)(struct uacce_device *uacce);
	int (*get_queue)(struct uacce_device *uacce, unsigned long arg,
			 struct uacce_queue *q);
	void (*put_queue)(struct uacce_queue *q);
	int (*start_queue)(struct uacce_queue *q);
	void (*stop_queue)(struct uacce_queue *q);
	void (*dump_queue)(const struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma,
		    struct uacce_qfile_region *qfr);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
		      unsigned long arg);
	enum uacce_dev_state (*get_isolate_state)(struct uacce_device *uacce);
	int (*isolate_err_threshold_write)(struct uacce_device *uacce, u32 num);
	u32 (*isolate_err_threshold_read)(struct uacce_device *uacce);
	enum uacce_dev_state (*get_dev_state)(struct uacce_device *uacce);
};

/**
 * struct uacce_interface - interface required for uacce_register()
 * @name: the uacce device name.  Will show up in sysfs
 * @flags: uacce device attributes
 * @ops: pointer to the struct uacce_ops
 */
struct uacce_interface {
	char name[UACCE_MAX_NAME_SIZE];
	unsigned int flags;
	const struct uacce_ops *ops;
};

enum uacce_dev_state {
	UACCE_DEV_ERR = -1,
	UACCE_DEV_NORMAL,
	UACCE_DEV_ISOLATE,
};

enum uacce_q_state {
	UACCE_Q_ZOMBIE = 0,
	UACCE_Q_INIT,
	UACCE_Q_STARTED,
};

/**
 * struct uacce_queue
 * @uacce: pointer to uacce
 * @priv: private pointer
 * @wait: wait queue head
 * @list: index into uacce queues list
 * @qfrs: pointer of qfr regions
 * @mutex: protects queue state
 * @state: queue state machine
 * @pasid: pasid associated to the mm
 * @handle: iommu_sva handle returned by iommu_sva_bind_device()
 */
struct uacce_queue {
	struct uacce_device *uacce;
	u32 flags;
	atomic_t status;
	void *priv;
	wait_queue_head_t wait;
	struct list_head list;
	struct uacce_qfile_region *qfrs[UACCE_MAX_REGION];
	struct mutex mutex;
	struct file *filep;
	enum uacce_q_state state;
	u32 pasid;
	struct iommu_sva *handle;
};

/**
 * struct uacce_device
 * @algs: supported algorithms
 * @api_ver: api version
 * @ops: pointer to the struct uacce_ops
 * @qf_pg_num: page numbers of the queue file regions
 * @parent: pointer to the parent device
 * @is_vf: whether virtual function
 * @flags: uacce attributes
 * @dev_id: id of the uacce device
 * @cdev: cdev of the uacce
 * @dev: dev of the uacce
 * @mutex: protects uacce operation
 * @priv: private pointer of the uacce
 * @queues: list of queues
 * @ref: reference of the uacce
 * @inode: core vfs
 */
struct uacce_device {
	const char *algs;
	const char *api_ver;
	int status;
	const struct uacce_ops *ops;
	unsigned long qf_pg_num[UACCE_MAX_REGION];
	struct device *parent;
	bool is_vf;
	u32 flags;
	u32 dev_id;
	struct cdev *cdev;
	struct device dev;
	struct mutex mutex;
	void *priv;
	atomic_t ref;
	struct uacce_err_isolate *isolate;
	struct list_head queues;
	struct inode *inode;
};

#if IS_ENABLED(CONFIG_UACCE)

struct uacce_device *uacce_alloc(struct device *parent,
				 struct uacce_interface *interface);
int uacce_register(struct uacce_device *uacce);
void uacce_remove(struct uacce_device *uacce);
struct uacce_device *dev_to_uacce(struct device *dev);
void uacce_wake_up(struct uacce_queue *q);
#else /* CONFIG_UACCE */

static inline
struct uacce_device *uacce_alloc(struct device *parent,
				 struct uacce_interface *interface)
{
	return ERR_PTR(-ENODEV);
}

static inline int uacce_register(struct uacce_device *uacce)
{
	return -EINVAL;
}

static inline void uacce_remove(struct uacce_device *uacce) {}

static inline struct uacce_device *dev_to_uacce(struct device *dev)
{
	return NULL;
}
static inline void uacce_wake_up(struct uacce_queue *q) {}
#endif /* CONFIG_UACCE */

#endif /* _LINUX_UACCE_H */
