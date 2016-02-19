/*
 * file : ne_ivshmem_basic_ldd.c 
 * desc : demo linux device driver for the QEMU ivshmem PCI device 
 *
 * notes: This is a skeleton version of "kvm_ivshmem.c" by 
 *        Cam Macdonell <cam@cs.ualberta.ca>, Copyright 2009, GPLv2
 *        See git://gitorious.org/nahanni/guest-code.git
 *
 * Siro Mugabi, nairobi-embedded.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "%s:%d:: " fmt, __func__, __LINE__
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/ratelimit.h>

#define IVSHMEM_DEV_NAME "ivshmem"
/* ============================================================
 *                         PCI SPECIFIC 
 * ============================================================ */
#include <linux/pci.h>

static struct {
        /* (mmio) control registers i.e. the "register memory region" */
        void __iomem    *regs_base_addr;
        resource_size_t regs_start;
        resource_size_t regs_len;
        /* data mmio region */
        void __iomem    *data_base_addr;
        resource_size_t data_mmio_start;
        resource_size_t data_mmio_len;
        /* irq handling */
        unsigned int    irq;
} ivshmem_dev;

static struct pci_device_id ivshmem_id_table[] = {
        { 0x1af4, 0x1110, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
        { 0 },
};
MODULE_DEVICE_TABLE (pci, ivshmem_id_table);

#define IVSHMEM_IRQ_ID "ivshmem_irq_id"

/*  relevant control register offsets */
enum {
        IntrMask        = 0x00,    /* Interrupt Mask */
        IntrStatus      = 0x04,    /* Interrupt Status */
};

static irqreturn_t ivshmem_interrupt (int irq, void *dev_id)
{
        u32 status;

        if (unlikely(strcmp((char*)dev_id, IVSHMEM_IRQ_ID)))
                return IRQ_NONE;

        status = readl(ivshmem_dev.regs_base_addr + IntrStatus);
        if (!status || (status == 0xFFFFFFFF))
                return IRQ_NONE;

        pr_info_ratelimited("interrupt (status = 0x%04x)\n", status);
        return IRQ_HANDLED;
}

static int ivshmem_probe(struct pci_dev *pdev,
                         const struct pci_device_id *pdev_id) 
{

        int err;
        struct device *dev = &pdev->dev;

        if((err = pci_enable_device(pdev))){
                dev_err(dev, "pci_enable_device probe error %d for device %s\n",
                        err, pci_name(pdev));
                return err;
        }

        if((err = pci_request_regions(pdev, IVSHMEM_DEV_NAME)) < 0){
                dev_err(dev, "pci_request_regions error %d\n", err);
                goto pci_disable;
        }

        /* bar2: data mmio region */    
        ivshmem_dev.data_mmio_start = pci_resource_start(pdev, 2);
        ivshmem_dev.data_mmio_len   = pci_resource_len(pdev, 2);
        ivshmem_dev.data_base_addr = pci_iomap(pdev, 2, 0);
        if (!ivshmem_dev.data_base_addr) {
                dev_err(dev, "cannot iomap region of size %lu\n",
                             (unsigned long)ivshmem_dev.data_mmio_len);
                goto pci_release;
        }
        dev_info(dev, "data_mmio iomap base = 0x%lx \n", 
                        (unsigned long) ivshmem_dev.data_base_addr);
        dev_info(dev, "data_mmio_start = 0x%lx data_mmio_len = %lu\n",
                        (unsigned long)ivshmem_dev.data_mmio_start, 
                        (unsigned long)ivshmem_dev.data_mmio_len);

        /* bar0: control registers */
        ivshmem_dev.regs_start =  pci_resource_start(pdev, 0);
        ivshmem_dev.regs_len = pci_resource_len(pdev, 0);
        ivshmem_dev.regs_base_addr = pci_iomap(pdev, 0, 0x100);
        if (!ivshmem_dev.regs_base_addr) {
                dev_err(dev, "cannot ioremap registers of size %lu\n",
                             (unsigned long)ivshmem_dev.regs_len);
                goto reg_release;
        }

        /* interrupts: set all masks */
        writel(0xffffffff, ivshmem_dev.regs_base_addr + IntrMask);
        if (request_irq(pdev->irq, ivshmem_interrupt, IRQF_SHARED,
                                        IVSHMEM_DEV_NAME, IVSHMEM_IRQ_ID)) 
                dev_err(dev, "request_irq %d error\n", pdev->irq);

        dev_info(dev, "regs iomap base = 0x%lx, irq = %u\n",
                        (unsigned long)ivshmem_dev.regs_base_addr, pdev->irq);
        dev_info(dev, "regs_addr_start = 0x%lx regs_len = %lu\n",
                        (unsigned long)ivshmem_dev.regs_start, 
                        (unsigned long)ivshmem_dev.regs_len);

        return 0;

reg_release:
        pci_iounmap(pdev, ivshmem_dev.data_base_addr);
pci_release:
        pci_release_regions(pdev);
pci_disable:
        pci_disable_device(pdev);
        return -EBUSY;
}

static void ivshmem_remove(struct pci_dev* pdev)
{

        free_irq(pdev->irq, IVSHMEM_IRQ_ID);
        pci_iounmap(pdev, ivshmem_dev.regs_base_addr);
        pci_iounmap(pdev, ivshmem_dev.data_base_addr);
        pci_release_regions(pdev);
        pci_disable_device(pdev);

}

static struct pci_driver ivshmem_pci_driver = {
        .name      = IVSHMEM_DEV_NAME, 
        .id_table  = ivshmem_id_table,
        .probe     = ivshmem_probe,
        .remove    = ivshmem_remove,
};

/* ============================================================
 *                    THE FILE OPS
 * ============================================================ */
static int ivshmem_major;
#define IVSHMEM_MINOR 0

static int ivshmem_mmap(struct file *filp, struct vm_area_struct * vma)
{
        unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;

        if((offset + (vma->vm_end - vma->vm_start)) > ivshmem_dev.data_mmio_len)
            return -EINVAL;

        offset += (unsigned long)ivshmem_dev.data_mmio_start;

        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

        if(io_remap_pfn_range(vma, vma->vm_start,
                              offset >> PAGE_SHIFT,
                              vma->vm_end - vma->vm_start,
                              vma->vm_page_prot))
                return -EAGAIN;

        return 0;
}

static int ivshmem_open(struct inode * inode, struct file * filp)
{
         if (MINOR(inode->i_rdev) != IVSHMEM_MINOR) {
                pr_info("minor: %d\n", IVSHMEM_MINOR);
                return -ENODEV;
         }
         return 0;
}

static int ivshmem_release(struct inode * inode, struct file * filp)
{
         return 0;
}

static const struct file_operations ivshmem_ops = {
        .owner   = THIS_MODULE,
        .open    = ivshmem_open,
        .mmap    = ivshmem_mmap,
        .release = ivshmem_release,
};

/* ============================================================
 *                  MODULE INIT/EXIT
 * ============================================================ */
#define IVSHMEM_DEVS_NUM 1          /* number of devices */
static struct cdev cdev;            /* char device abstraction */ 
static struct class *ivshmem_class; /* linux device model */

static int __init ivshmem_init (void)
{
        int err = -ENOMEM;

        /* obtain major */
        dev_t mjr = MKDEV(ivshmem_major, 0);
        if((err = alloc_chrdev_region(&mjr, 0, IVSHMEM_DEVS_NUM, IVSHMEM_DEV_NAME)) < 0){
                pr_err("alloc_chrdev_region error\n");
                return err;
        }
        ivshmem_major = MAJOR(mjr);

        /* connect fops with the cdev */
        cdev_init(&cdev, &ivshmem_ops);
        cdev.owner = THIS_MODULE;

        /* connect major/minor to the cdev */
        {
                dev_t devt;
                devt = MKDEV(ivshmem_major, IVSHMEM_MINOR);

                if((err = cdev_add(&cdev, devt, 1))){
                        pr_err("cdev_add error\n");
                        goto unregister_dev;
                }
        }

        /* populate sysfs entries */
        if(!(ivshmem_class = class_create(THIS_MODULE, IVSHMEM_DEV_NAME))){
                pr_err("class_create error\n");
                goto del_cdev;
        }

        /* create udev '/dev' node */
        {
                dev_t devt = MKDEV(ivshmem_major, IVSHMEM_MINOR);   
                if(!(device_create(ivshmem_class, NULL, devt, NULL, IVSHMEM_DEV_NAME"%d", IVSHMEM_MINOR))){
                        pr_err("device_create error\n");
                        goto destroy_class;
                }
        }

        /* register pci device driver */
        if((err = pci_register_driver(&ivshmem_pci_driver)) < 0){
                pr_err("pci_register_driver error\n");
                goto exit;
        }

        return 0;

exit:
        device_destroy(ivshmem_class, MKDEV(ivshmem_major, IVSHMEM_MINOR));
destroy_class:
        class_destroy(ivshmem_class);
del_cdev:
        cdev_del(&cdev);
unregister_dev:
        unregister_chrdev_region(MKDEV(ivshmem_major, IVSHMEM_MINOR), IVSHMEM_DEVS_NUM);

        return err;
}

static void __exit ivshmem_fini(void)
{
        pci_unregister_driver (&ivshmem_pci_driver);
        device_destroy(ivshmem_class, MKDEV(ivshmem_major, IVSHMEM_MINOR));
        class_destroy(ivshmem_class);
        cdev_del(&cdev);
        unregister_chrdev_region(MKDEV(ivshmem_major, IVSHMEM_MINOR), IVSHMEM_DEVS_NUM);
}

module_init(ivshmem_init);
module_exit(ivshmem_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Demo module for QEMU ivshmem virtual pci device");
