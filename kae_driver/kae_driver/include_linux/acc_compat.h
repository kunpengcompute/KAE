/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (c) 2018-2019 HiSilicon Limited. */
#ifndef __ACC_COMPAT_H
#define __ACC_COMPAT_H

#include <linux/pci-dma-compat.h>

#define CONFIG_CRYPTO_QM_UACCE 1
#ifndef pci_emerg
#define pci_emerg(pdev, fmt, arg...)   dev_emerg(&(pdev)->dev, fmt, ##arg)
#endif

#ifndef pci_err
#define pci_err(pdev, fmt, arg...)     dev_err(&(pdev)->dev, fmt, ##arg)
#endif

#ifndef pci_warn
#define pci_warn(pdev, fmt, arg...)    dev_warn(&(pdev)->dev, fmt, ##arg)
#endif

#ifndef pci_info
#define pci_info(pdev, fmt, arg...)    dev_info(&(pdev)->dev, fmt, ##arg)
#endif

#endif
