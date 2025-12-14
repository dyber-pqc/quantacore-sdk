/*
 * QUAC 100 Mock Kernel Module
 *
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 *
 * This is a software-only kernel module that simulates the QUAC 100
 * hardware for testing purposes. It creates the same device nodes
 * and sysfs entries as the real driver, but implements all operations
 * in software.
 *
 * BUILD:
 *   make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 *
 * LOAD:
 *   sudo insmod quac100_mock.ko [options]
 *
 * OPTIONS:
 *   num_devices=N     Number of simulated devices (default: 1, max: 4)
 *   sim_latency_us=N  Simulated operation latency in microseconds (default: 100)
 *   fail_rate=N       Simulated failure rate per 10000 ops (default: 0)
 *   debug_level=N     Debug verbosity 0-7 (default: 3)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/version.h>

#define DRIVER_NAME "quac100_mock"
#define DRIVER_VERSION "1.0.0-mock"
#define MAX_DEVICES 4

/* Module parameters */
static int num_devices = 1;
static int sim_latency_us = 100;
static int fail_rate = 0; /* per 10000 operations */
static int debug_level = 3;

module_param(num_devices, int, 0444);
MODULE_PARM_DESC(num_devices, "Number of simulated devices (1-4)");

module_param(sim_latency_us, int, 0644);
MODULE_PARM_DESC(sim_latency_us, "Simulated operation latency in microseconds");

module_param(fail_rate, int, 0644);
MODULE_PARM_DESC(fail_rate, "Simulated failure rate per 10000 operations");

module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug verbosity level 0-7");

/* Debug macros */
#define QUAC_ERR(fmt, ...) pr_err(DRIVER_NAME ": " fmt, ##__VA_ARGS__)
#define QUAC_WARN(fmt, ...) pr_warn(DRIVER_NAME ": " fmt, ##__VA_ARGS__)
#define QUAC_INFO(fmt, ...) pr_info(DRIVER_NAME ": " fmt, ##__VA_ARGS__)
#define QUAC_DBG(fmt, ...)                                 \
    do                                                     \
    {                                                      \
        if (debug_level >= 4)                              \
            pr_debug(DRIVER_NAME ": " fmt, ##__VA_ARGS__); \
    } while (0)

/* IOCTL commands (must match quac100_ioctl.h) */
#define QUAC_IOCTL_MAGIC 'Q'
#define QUAC_IOC_GET_VERSION _IOR(QUAC_IOCTL_MAGIC, 0x00, uint32_t)
#define QUAC_IOC_GET_INFO _IOR(QUAC_IOCTL_MAGIC, 0x01, struct quac_mock_info)
#define QUAC_IOC_RESET _IOW(QUAC_IOCTL_MAGIC, 0x04, uint32_t)
#define QUAC_IOC_KEM_KEYGEN _IOWR(QUAC_IOCTL_MAGIC, 0x40, struct quac_mock_kem)
#define QUAC_IOC_RANDOM _IOWR(QUAC_IOCTL_MAGIC, 0x46, struct quac_mock_random)
#define QUAC_IOC_SELF_TEST _IOWR(QUAC_IOCTL_MAGIC, 0xE0, struct quac_mock_selftest)

/* Mock data structures */
struct quac_mock_info
{
    uint32_t version;
    uint32_t device_index;
    char serial[32];
    uint32_t capabilities;
    uint32_t status;
    int32_t temperature;
    uint32_t entropy_available;
};

struct quac_mock_kem
{
    uint32_t algorithm;
    uint32_t flags;
    uint64_t pk_addr;
    uint32_t pk_size;
    uint64_t sk_addr;
    uint32_t sk_size;
    int32_t result;
};

struct quac_mock_random
{
    uint64_t buf_addr;
    uint32_t length;
    uint32_t quality;
    int32_t result;
};

struct quac_mock_selftest
{
    uint32_t tests;
    uint32_t tests_passed;
    uint32_t tests_failed;
    int32_t result;
};

/* Device structure */
struct quac_mock_device
{
    int index;
    struct cdev cdev;
    struct device *dev;
    struct mutex lock;

    /* Simulated state */
    uint64_t ops_completed;
    uint64_t ops_failed;
    int32_t temperature;
    uint32_t entropy_pool;
    bool initialized;

    /* Statistics */
    uint64_t kem_keygens;
    uint64_t random_bytes;
    uint64_t self_tests;
};

/* Global state */
static dev_t quac_dev_num;
static struct class *quac_class;
static struct quac_mock_device *devices[MAX_DEVICES];

/*
 * Simulated cryptographic operations
 */

static bool should_fail(void)
{
    if (fail_rate <= 0)
        return false;
    return (get_random_u32() % 10000) < fail_rate;
}

static void simulate_latency(void)
{
    if (sim_latency_us > 0)
        udelay(sim_latency_us);
}

static int mock_kem_keygen(struct quac_mock_device *dev,
                           struct quac_mock_kem __user *arg)
{
    struct quac_mock_kem kem;
    uint8_t *pk_buf = NULL;
    uint8_t *sk_buf = NULL;
    int ret = 0;

    if (copy_from_user(&kem, arg, sizeof(kem)))
        return -EFAULT;

    QUAC_DBG("KEM keygen: algo=%u, pk_size=%u, sk_size=%u\n",
             kem.algorithm, kem.pk_size, kem.sk_size);

    simulate_latency();

    if (should_fail())
    {
        kem.result = -1; /* QUAC_ERROR_KEY_GENERATION_FAILED */
        dev->ops_failed++;
        goto out;
    }

    /* Allocate buffers */
    pk_buf = kmalloc(kem.pk_size, GFP_KERNEL);
    sk_buf = kmalloc(kem.sk_size, GFP_KERNEL);
    if (!pk_buf || !sk_buf)
    {
        ret = -ENOMEM;
        goto cleanup;
    }

    /* Generate mock key material (random data) */
    get_random_bytes(pk_buf, kem.pk_size);
    get_random_bytes(sk_buf, kem.sk_size);

    /* Copy to userspace */
    if (copy_to_user((void __user *)kem.pk_addr, pk_buf, kem.pk_size) ||
        copy_to_user((void __user *)kem.sk_addr, sk_buf, kem.sk_size))
    {
        ret = -EFAULT;
        goto cleanup;
    }

    dev->kem_keygens++;
    dev->ops_completed++;
    kem.result = 0; /* QUAC_SUCCESS */

out:
    if (copy_to_user(arg, &kem, sizeof(kem)))
        ret = -EFAULT;

cleanup:
    kfree(pk_buf);
    kfree(sk_buf);
    return ret;
}

static int mock_random(struct quac_mock_device *dev,
                       struct quac_mock_random __user *arg)
{
    struct quac_mock_random rnd;
    uint8_t *buf = NULL;
    int ret = 0;

    if (copy_from_user(&rnd, arg, sizeof(rnd)))
        return -EFAULT;

    QUAC_DBG("Random: length=%u, quality=%u\n", rnd.length, rnd.quality);

    if (rnd.length > (1024 * 1024))
    {
        rnd.result = -1; /* Too large */
        goto out;
    }

    simulate_latency();

    if (should_fail())
    {
        rnd.result = -1;
        dev->ops_failed++;
        goto out;
    }

    buf = kmalloc(rnd.length, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    /* Generate random bytes using kernel RNG */
    get_random_bytes(buf, rnd.length);

    if (copy_to_user((void __user *)rnd.buf_addr, buf, rnd.length))
    {
        ret = -EFAULT;
        goto cleanup;
    }

    dev->random_bytes += rnd.length;
    dev->ops_completed++;
    dev->entropy_pool = max(dev->entropy_pool, 8192u) - (rnd.length * 8 / 10);
    rnd.result = 0;

out:
    if (copy_to_user(arg, &rnd, sizeof(rnd)))
        ret = -EFAULT;

cleanup:
    kfree(buf);
    return ret;
}

static int mock_self_test(struct quac_mock_device *dev,
                          struct quac_mock_selftest __user *arg)
{
    struct quac_mock_selftest test;

    if (copy_from_user(&test, arg, sizeof(test)))
        return -EFAULT;

    QUAC_INFO("Running self-test: mask=0x%x\n", test.tests);

    /* Simulate test execution time */
    msleep(100);

    /* All tests pass in mock mode (unless failure injection enabled) */
    if (should_fail())
    {
        test.tests_passed = test.tests & 0x0F;
        test.tests_failed = test.tests & 0xF0;
        test.result = -1;
    }
    else
    {
        test.tests_passed = test.tests;
        test.tests_failed = 0;
        test.result = 0;
    }

    dev->self_tests++;

    if (copy_to_user(arg, &test, sizeof(test)))
        return -EFAULT;

    return 0;
}

/*
 * File operations
 */

static int quac_mock_open(struct inode *inode, struct file *file)
{
    int minor = iminor(inode);
    struct quac_mock_device *dev;

    if (minor >= num_devices)
        return -ENODEV;

    dev = devices[minor];
    if (!dev)
        return -ENODEV;

    file->private_data = dev;
    QUAC_DBG("Device %d opened\n", minor);

    return 0;
}

static int quac_mock_release(struct inode *inode, struct file *file)
{
    struct quac_mock_device *dev = file->private_data;
    QUAC_DBG("Device %d closed\n", dev->index);
    return 0;
}

static long quac_mock_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct quac_mock_device *dev = file->private_data;
    int ret = 0;

    if (!dev)
        return -ENODEV;

    mutex_lock(&dev->lock);

    switch (cmd)
    {
    case QUAC_IOC_GET_VERSION:
    {
        uint32_t version = 0x00010000; /* 1.0.0 */
        if (copy_to_user((void __user *)arg, &version, sizeof(version)))
            ret = -EFAULT;
    }
    break;

    case QUAC_IOC_GET_INFO:
    {
        struct quac_mock_info info = {
            .version = 0x00010000,
            .device_index = dev->index,
            .capabilities = 0x800000FF, /* Simulator + all algorithms */
            .status = 0,                /* OK */
            .temperature = dev->temperature,
            .entropy_available = dev->entropy_pool,
        };
        snprintf(info.serial, sizeof(info.serial), "MOCK%04d", dev->index);

        if (copy_to_user((void __user *)arg, &info, sizeof(info)))
            ret = -EFAULT;
    }
    break;

    case QUAC_IOC_RESET:
        QUAC_INFO("Device %d reset\n", dev->index);
        dev->ops_completed = 0;
        dev->ops_failed = 0;
        dev->entropy_pool = 8192;
        break;

    case QUAC_IOC_KEM_KEYGEN:
        ret = mock_kem_keygen(dev, (void __user *)arg);
        break;

    case QUAC_IOC_RANDOM:
        ret = mock_random(dev, (void __user *)arg);
        break;

    case QUAC_IOC_SELF_TEST:
        ret = mock_self_test(dev, (void __user *)arg);
        break;

    default:
        QUAC_DBG("Unknown ioctl: 0x%x\n", cmd);
        ret = -ENOTTY;
    }

    mutex_unlock(&dev->lock);
    return ret;
}

static const struct file_operations quac_mock_fops = {
    .owner = THIS_MODULE,
    .open = quac_mock_open,
    .release = quac_mock_release,
    .unlocked_ioctl = quac_mock_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = quac_mock_ioctl,
#endif
};

/*
 * Sysfs attributes
 */

static ssize_t temperature_show(struct device *dev,
                                struct device_attribute *attr, char *buf)
{
    struct quac_mock_device *qdev = dev_get_drvdata(dev);
    return sprintf(buf, "%d\n", qdev->temperature);
}

static ssize_t entropy_show(struct device *dev,
                            struct device_attribute *attr, char *buf)
{
    struct quac_mock_device *qdev = dev_get_drvdata(dev);
    return sprintf(buf, "%u\n", qdev->entropy_pool);
}

static ssize_t ops_completed_show(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
    struct quac_mock_device *qdev = dev_get_drvdata(dev);
    return sprintf(buf, "%llu\n", qdev->ops_completed);
}

static ssize_t ops_failed_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    struct quac_mock_device *qdev = dev_get_drvdata(dev);
    return sprintf(buf, "%llu\n", qdev->ops_failed);
}

static ssize_t simulator_show(struct device *dev,
                              struct device_attribute *attr, char *buf)
{
    return sprintf(buf, "1\n"); /* Always 1 for mock device */
}

static DEVICE_ATTR_RO(temperature);
static DEVICE_ATTR_RO(entropy);
static DEVICE_ATTR_RO(ops_completed);
static DEVICE_ATTR_RO(ops_failed);
static DEVICE_ATTR_RO(simulator);

static struct attribute *quac_mock_attrs[] = {
    &dev_attr_temperature.attr,
    &dev_attr_entropy.attr,
    &dev_attr_ops_completed.attr,
    &dev_attr_ops_failed.attr,
    &dev_attr_simulator.attr,
    NULL,
};

static const struct attribute_group quac_mock_attr_group = {
    .attrs = quac_mock_attrs,
};

static const struct attribute_group *quac_mock_attr_groups[] = {
    &quac_mock_attr_group,
    NULL,
};

/*
 * Module init/exit
 */

static int __init quac_mock_init(void)
{
    int ret, i;

    QUAC_INFO("Loading %s version %s\n", DRIVER_NAME, DRIVER_VERSION);
    QUAC_INFO("Simulating %d device(s), latency=%dus, fail_rate=%d/10000\n",
              num_devices, sim_latency_us, fail_rate);

    if (num_devices < 1 || num_devices > MAX_DEVICES)
    {
        QUAC_ERR("Invalid num_devices: %d (must be 1-%d)\n",
                 num_devices, MAX_DEVICES);
        return -EINVAL;
    }

    /* Allocate device numbers */
    ret = alloc_chrdev_region(&quac_dev_num, 0, num_devices, "quac100");
    if (ret < 0)
    {
        QUAC_ERR("Failed to allocate char dev region\n");
        return ret;
    }

    /* Create device class */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    quac_class = class_create("quac100");
#else
    quac_class = class_create(THIS_MODULE, "quac100");
#endif
    if (IS_ERR(quac_class))
    {
        ret = PTR_ERR(quac_class);
        QUAC_ERR("Failed to create class\n");
        goto err_class;
    }

    /* Create devices */
    for (i = 0; i < num_devices; i++)
    {
        struct quac_mock_device *dev;

        dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
        {
            ret = -ENOMEM;
            goto err_devices;
        }

        dev->index = i;
        mutex_init(&dev->lock);
        dev->temperature = 45 + (get_random_u32() % 10); /* 45-55°C */
        dev->entropy_pool = 8192;
        dev->initialized = true;

        /* Initialize cdev */
        cdev_init(&dev->cdev, &quac_mock_fops);
        dev->cdev.owner = THIS_MODULE;

        ret = cdev_add(&dev->cdev, MKDEV(MAJOR(quac_dev_num), i), 1);
        if (ret)
        {
            QUAC_ERR("Failed to add cdev %d\n", i);
            kfree(dev);
            goto err_devices;
        }

        /* Create device node */
        dev->dev = device_create_with_groups(quac_class, NULL,
                                             MKDEV(MAJOR(quac_dev_num), i),
                                             dev, quac_mock_attr_groups,
                                             "quac100_%d", i);
        if (IS_ERR(dev->dev))
        {
            ret = PTR_ERR(dev->dev);
            QUAC_ERR("Failed to create device %d\n", i);
            cdev_del(&dev->cdev);
            kfree(dev);
            goto err_devices;
        }

        devices[i] = dev;
        QUAC_INFO("Created mock device /dev/quac100_%d\n", i);
    }

    QUAC_INFO("Module loaded successfully\n");
    return 0;

err_devices:
    for (i--; i >= 0; i--)
    {
        if (devices[i])
        {
            device_destroy(quac_class, MKDEV(MAJOR(quac_dev_num), i));
            cdev_del(&devices[i]->cdev);
            kfree(devices[i]);
        }
    }
    class_destroy(quac_class);

err_class:
    unregister_chrdev_region(quac_dev_num, num_devices);
    return ret;
}

static void __exit quac_mock_exit(void)
{
    int i;

    QUAC_INFO("Unloading module\n");

    for (i = 0; i < num_devices; i++)
    {
        if (devices[i])
        {
            QUAC_INFO("Device %d stats: ops=%llu, failed=%llu, keygens=%llu, random=%llu bytes\n",
                      i, devices[i]->ops_completed, devices[i]->ops_failed,
                      devices[i]->kem_keygens, devices[i]->random_bytes);

            device_destroy(quac_class, MKDEV(MAJOR(quac_dev_num), i));
            cdev_del(&devices[i]->cdev);
            kfree(devices[i]);
        }
    }

    class_destroy(quac_class);
    unregister_chrdev_region(quac_dev_num, num_devices);

    QUAC_INFO("Module unloaded\n");
}

module_init(quac_mock_init);
module_exit(quac_mock_exit);

MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("Dyber, Inc.");
MODULE_DESCRIPTION("QUAC 100 Mock Driver for Testing");
MODULE_VERSION(DRIVER_VERSION);