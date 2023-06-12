/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include "kshram.h"
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/path.h>

#define num 8
#define MEM_KZALLOC_SIZE 4096

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;
char *kshram_kmem[num];
int kshram_kmem_size[num];

static int kshram_index(char* filename){
	if(strcmp(filename,"kshram0")==0){
		return 0;
	}else if(strcmp(filename,"kshram1")==0){
		return 1;
	}else if(strcmp(filename,"kshram2")==0){
		return 2;
	}else if(strcmp(filename,"kshram3")==0){
		return 3;
	}else if(strcmp(filename,"kshram4")==0){
		return 4;
	}else if(strcmp(filename,"kshram5")==0){
		return 5;
	}else if(strcmp(filename,"kshram6")==0){
		return 6;
	}else{
		return 7;
	}

}

static int kshram_dev_open(struct inode *i, struct file *f) {
	// char *filename = f->f_path.dentry->d_iname;
	// printk("name %s\n",filename);
	// printk(KERN_INFO "kshrammod: device opened.\n");
	return 0;
}

static int kshram_dev_close(struct inode *i, struct file *f) {
	// printk(KERN_INFO "kshrammod: device closed.\n");
	return 0;
}

static ssize_t kshram_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "kshrammod: read %zu bytes @ %llu.\n", len, *off);
	int res = -1;
    char *tmp;
	int index = kshram_index(f->f_path.dentry->d_iname);
    // printk("copy data to the user space\n");
    tmp = kshram_kmem[index];
    if (len > MEM_KZALLOC_SIZE)                   //size overflow
        len = MEM_KZALLOC_SIZE;
    if(tmp != NULL)
    	res = copy_to_user(buf, tmp, len);     //write to kernel mem
    if (res == 0){
        // printk("copy data success and the data is:%s\n", tmp);        
		return len;
    }else{
        // printk("copy data fail to the user space\n");
        return 0;
    }

}

static ssize_t kshram_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	// printk(KERN_INFO "kshrammod: write %zu bytes @ %llu.\n", len, *off);
	int res = -1;
    char *tmp;
	int index = kshram_index(f->f_path.dentry->d_iname);
	// printk("read data from the user space\n");
    tmp = kshram_kmem[index];
    if (len > MEM_KZALLOC_SIZE)                   //size overflow
        len = MEM_KZALLOC_SIZE;
    if(tmp != NULL)
    	res = copy_from_user(tmp, buf, len);   //write to kernel mem
    if (res == 0){
        // printk("read data success and the data is:%s\n", tmp);   
        return len;
    }else{
        // printk("read data from user space fail\n");
        return 0;
    }
	return len;
}

static long kshram_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "kshrammod: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	int index;
	switch(cmd){
		case KSHRAM_GETSLOTS :
			// printk(KERN_INFO "kshrammod: ioctl cmd KSHRAM_GETSLOTS.\n");
			return num;
			break;
		case KSHRAM_GETSIZE :
			// printk(KERN_INFO "kshrammod: ioctl cmd KSHRAM_GETSIZE\n");
			index = kshram_index(f->f_path.dentry->d_iname);
			return kshram_kmem_size[index];
			break;
		case KSHRAM_SETSIZE :
			// printk(KERN_INFO "kshrammod: ioctl cmd KSHRAM_SETSIZE\n");
			index = kshram_index(f->f_path.dentry->d_iname);
			kshram_kmem[index] = krealloc(kshram_kmem[index], arg, GFP_KERNEL); 
			if(kshram_kmem[index] == NULL){
				// printk("krealloc fail\n");
			}else{
				kshram_kmem_size[index] = arg;
				// printk("krealloc success nuw addr %px new size %lu\n",kshram_kmem[index],arg);
			}
			break;
		default:
			break;
	}
	return 0;
}

static int kshram_dev_mmap(struct file *f, struct vm_area_struct *vma){
	// printk(KERN_INFO "kshrammod: mmap\n");
	int index = kshram_index(f->f_path.dentry->d_iname);
	unsigned long len = vma->vm_end - vma->vm_start;
	int ret ;
	
	unsigned long pfn = page_to_pfn(virt_to_page((unsigned long)kshram_kmem[index]));
	ret = remap_pfn_range(vma, vma->vm_start, pfn, len, vma->vm_page_prot);
	if (ret < 0) {
		pr_err("could not map the address area\n");
		return -EIO;
	}else{
		printk("kshram/mmap: idx %d size %d\n", index, kshram_kmem_size[index]);
	}

	return 0;
}


static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.read = kshram_dev_read,
	.write = kshram_dev_write,
	.mmap = kshram_dev_mmap,
	.unlocked_ioctl = kshram_dev_ioctl,
	.release = kshram_dev_close
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	
	for(int i = 0; i < num; i++){
		char buf[64];
		// char* pos = kshram_kmem[i];
		sprintf(buf,"0%d : %d\n",i,kshram_kmem_size[i]);
		seq_printf(m, buf);
	}
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{
	for(int i = 0; i < num; i++){
		kshram_kmem[i]=(char *)kzalloc(MEM_KZALLOC_SIZE, GFP_KERNEL);//allocate num mem
		SetPageReserved(virt_to_page((unsigned long)kshram_kmem[i]));
		kshram_kmem_size[i] = MEM_KZALLOC_SIZE;
		if(kshram_kmem[i] == NULL ){
        	// printk("kzalloc failed! \n");
		}else{
			printk("kshram%d: %d bytes allocated @ 0x%lx\n", i, kshram_kmem_size[i], (unsigned long)kshram_kmem[i] );
		}
		
	}

	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "kdev") < 0)
		return -1;
	// printk(KERN_INFO "Major = %d Minor = %d.\n", MAJOR(devnum), MINOR(devnum));
	if((clazz = class_create(THIS_MODULE, "kclass")) == NULL)
		goto release_region;
	clazz->devnode = kshram_devnode;
	cdev_init(&c_dev, &kshram_dev_fops);
	if(cdev_add(&c_dev, devnum, 8) == -1)
		goto release_device;
	for(int i = 0; i < num; i ++){
		if(device_create(clazz, NULL, MKDEV(MAJOR(devnum),i), NULL, "kshram%d", i) == NULL)
			goto release_class;
	}
	
	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	
	for(int i = 0; i < num; i ++){
		if((kshram_kmem[i]) != NULL)
		{
			ClearPageReserved(virt_to_page(kshram_kmem[i]));
			kfree(kshram_kmem[i]); //释放由kzalloc( )所分配的内存空间
			// printk("%d kfree ok! \n",i);
		}
		// printk("exit! \n");
	}

	cdev_del(&c_dev);
	for (int i = 0; i < num; ++i)
		device_destroy(clazz, MKDEV(MAJOR(devnum),i));
	//device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);
	remove_proc_entry("kshram", NULL);
	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Man-Wen Su");
MODULE_DESCRIPTION("The unix programming course lab5 kernel module.");
