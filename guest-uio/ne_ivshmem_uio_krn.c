/*
 * file  : ne_ivshmem_uio_krn.c 
 * desc  : a demo uio device driver kernel stub for the QEMU ivshmem PCI device
 * notes : this file is a skeleton version of the original "uio_ivshmem.c" 
 *         uio driver by Cam Macdonell (C) 2009, GPLv2
 *         See "git://gitorious.org/nahanni/guest-code.git"
 *
 *         Also see:
 *         drivers/uio/uio-cif.c, (C) 2007 Hans J. Koch <hjk@linutronix.de>
 *
 * Siro Mugabi, nairobi-embedded.org
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uio_driver.h>

#define IntrStatus 0x04
#define IntrMask 0x00

struct ivshmem_info {
    struct uio_info *uio;
    struct pci_dev *dev;
};

static irqreturn_t ivshmem_handler(int irq, struct uio_info *dev_info)
{
    u32 status;

    if (!(status = readl(dev_info->mem[0].internal_addr + IntrStatus)))
        return IRQ_NONE;

    return IRQ_HANDLED;
}

static int ivshmem_pci_probe(struct pci_dev *dev,
                     const struct pci_device_id *id)
{
    struct uio_info *info;
    struct ivshmem_info *ivshmem_info;

    if (!(info = kzalloc(sizeof(struct uio_info), GFP_KERNEL))) {
        dev_err(&dev->dev, "kzalloc error!\n");
        return -ENOMEM;
    }

    if (!(ivshmem_info = kzalloc(sizeof(struct ivshmem_info), GFP_KERNEL))) {
        kfree(info);
        dev_err(&dev->dev, "kzalloc error!\n");
        return -ENOMEM;
    }

    if (pci_enable_device(dev)) {
        dev_err(&dev->dev, "pci_enable_device error!\n");
        goto out_free;
    }

    if (pci_request_regions(dev, "ivshmem")) {
        dev_err(&dev->dev, "pci_request_regions error!\n");
        goto out_disable;
    }

    /* ivshmem bar0: uio mapping 0 */
    if (!(info->mem[0].addr = pci_resource_start(dev, 0)))
        goto out_release;

    info->mem[0].size = pci_resource_len(dev, 0);

    if (!(info->mem[0].internal_addr = pci_ioremap_bar(dev, 0)))
        goto out_release;

    info->mem[0].memtype = UIO_MEM_PHYS;

    /* ivshmem bar2: uio mapping 1 */
    if (!(info->mem[1].addr = pci_resource_start(dev, 2)))
        goto out_unmap;

    info->mem[1].size = pci_resource_len(dev, 2);

    if (!(info->mem[1].internal_addr = pci_ioremap_bar(dev, 2)))
        goto out_unmap;

    info->mem[1].memtype = UIO_MEM_PHYS;

    ivshmem_info->uio = info;
    ivshmem_info->dev = dev;

    /* ivshmem kernel stub irq handler info for uio */
    info->irq = dev->irq;
    info->irq_flags = IRQF_SHARED;
    info->handler = ivshmem_handler;
    writel(0xffffffff, info->mem[0].internal_addr + IntrMask);

    /* misc sysfs info */
    info->name = "ivshmem";
    info->version = "0.1";

    /* register device driver with uio framework */
    if (uio_register_device(&dev->dev, info))
        goto out_unmap2;

    pci_set_drvdata(dev, info);

    return 0;

out_unmap2:
    iounmap(info->mem[2].internal_addr);
out_unmap:
    iounmap(info->mem[0].internal_addr);
out_release:
    dev_err(&dev->dev, "uio error!\n");
    pci_release_regions(dev);
out_disable:
    pci_disable_device(dev);
out_free:
    kfree(info);
    return -ENODEV;
}

static void ivshmem_pci_remove(struct pci_dev *dev)
{
    struct uio_info *info = pci_get_drvdata(dev);

    uio_unregister_device(info);
    pci_release_regions(dev);
    pci_disable_device(dev);
    pci_set_drvdata(dev, NULL);
    iounmap(info->mem[0].internal_addr);

    kfree(info);
}

static struct pci_device_id ivshmem_pci_ids[] = {
    { .vendor = 0x1af4, .device = 0x1110,
      .subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID,},
    {0,}
};
MODULE_DEVICE_TABLE(pci, ivshmem_pci_ids);

static struct pci_driver ivshmem_pci_driver = {
    .name = "uio_ivshmem",
    .id_table = ivshmem_pci_ids,
    .probe = ivshmem_pci_probe,
    .remove = ivshmem_pci_remove,
};

module_driver(ivshmem_pci_driver, pci_register_driver, pci_unregister_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Demo UIO device driver for QEMU ivshmem virtual PCI device");
