/*
 * Simple - REALLY simple memory mapping demonstration.
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 *
 * $Id: simple.c,v 1.12 2005/01/31 16:15:31 rubini Exp $
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>   /* printk() */
#include <linux/slab.h>   /* kmalloc() */
#include <linux/fs.h>       /* everything... */
#include <linux/errno.h>    /* error codes */
#include <linux/types.h>    /* size_t */
#include <linux/mm.h>
#include <linux/kdev_t.h>
#include <asm/page.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>	/* copy_*_user */
#include <linux/device.h>

static int simple_major = 0;
module_param(simple_major, int, 0);
MODULE_AUTHOR("Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");


struct scull_arg{
	int msr;
	int ecx;
	int ebx;
	int edx;
	int eax;
	int edi;
	int esi;
	int number;
	char* argv;
	uint16_t io_number;
	uint8_t data;
	unsigned long mem_address;
	unsigned long mem_data;
	//int ecx;
	//int ebx;
};
unsigned long gbuffer = 0;
int gcnt;
int gorder;

/*
 * Open the device; in fact, there's nothing to do here.
 */
static int simple_opend (struct inode *inode, struct file *filp)
{
	return 0;
}


/*
 * Closing is just as simpler.
 */
static int simple_release(struct inode *inode, struct file *filp)
{
	gbuffer =0;
	free_pages(gbuffer, gorder);
	return 0;
}



/*
 * Common VMA ops.
 */

void simple_vma_open(struct vm_area_struct *vma)
{

}

void simple_vma_close(struct vm_area_struct *vma)
{
}


/*
 * The remap_pfn_range version of mmap.  This one is heavily borrowed
 * from drivers/char/mem.c.
 */

static struct vm_operations_struct simple_remap_vm_ops = {
	.open =  simple_vma_open,
	.close = simple_vma_close,
};

static int simple_remap_mmap(struct file *filp, struct vm_area_struct *vma)
{
	if (remap_pfn_range(vma, vma->vm_start, __pa(gbuffer) >> PAGE_SHIFT,
			    vma->vm_end - vma->vm_start,
			    vma->vm_page_prot))
		return -EAGAIN;

	vma->vm_ops = &simple_remap_vm_ops;
	simple_vma_open(vma);
	return 0;
}



/*
 * Set up the cdev structure for a device.
 */
static void simple_setup_cdev(struct cdev *dev, int minor,
		struct file_operations *fops)
{
	int err, devno = MKDEV(simple_major, minor);
    
	cdev_init(dev, fops);
	dev->owner = THIS_MODULE;
	dev->ops = fops;
	err = cdev_add (dev, devno, 1);
	/* Fail gracefully if need be */
	if (err)
		printk (KERN_NOTICE "Error %d adding simple%d", err, minor);
}


#define SETLEN  (0x100)
#define RDMSR   (0x200)
#define WRMSR    (0x300)
#define WCMD    (0x400)
#define TEST   (0x500)
#define IOW   (0x600)
#define IOR   (0x700)
#define CPUID   (0x800)
#define MEMW   (0x900)
#define MEMR   (0xa00)
int glen;
long simple_ioctl(struct file *filp,
                 unsigned int cmd, unsigned long arg)
{

	int retval = 0;
	//unsigned long long vir;
	int i;
	unsigned long * virtual;
	struct page *page;
	struct scull_arg sarg;
  	if (copy_from_user(&sarg, (void __user *)arg, sizeof(struct scull_arg)))
		return retval;
	
	switch(cmd) {

	  case CPUID:
		__asm__ __volatile__("cpuid" : "=d"(sarg.edx), "=a"(sarg.eax) ,"=c"(sarg.ecx),"=b"(sarg.ebx): "a"(sarg.eax)/*: "%edx", "%eax"*/);
	    	break;
	
	  case SETLEN :

		if(gbuffer !=0 ){
				for (page = virt_to_page(gbuffer) ,i=0; i<gcnt; page++, i++)
					ClearPageReserved(page);
				free_pages(gbuffer, gorder);
				
		}
		glen = sarg.msr;
		gorder  = get_order(sarg.msr);
		gbuffer = __get_free_pages(GFP_DMA|GFP_ATOMIC, gorder);
		gcnt = 1<<gorder;
		for (page = virt_to_page(gbuffer), i=0; i<gcnt; page++, i++)
			SetPageReserved(page);
	
		break;

	
	  case RDMSR :
		if( sarg.msr == 0x8b){
			int eax_8b = 1;
			__asm__ __volatile__("cpuid" : "=d"(sarg.edx), "=a"(sarg.eax) ,"=c"(sarg.ecx),"=b"(sarg.ebx): "a"(eax_8b)/*: "%edx", "%eax"*/); 
	        	__asm__ __volatile__("rdmsr" : "=d"(sarg.edx), "=a"(sarg.eax) : "c"(sarg.msr) /*: "%edx", "%eax"*/);
			break;
		}
		else{
		//printk("MSR is %x, EAX is %x, EBX is %x, ECX is %x, EDX is %x\n",sarg.msr,sarg.eax,sarg.ebx,sarg.ecx,sarg.edx);
	        __asm__ __volatile__("rdmsr" : "=d"(sarg.edx), "=a"(sarg.eax) : "d"(sarg.edx), "a"(sarg.eax), "c"(sarg.msr), "D"(sarg.edi), "S"(sarg.esi) /*: "%edx", "%eax"*/);
		}
		//rdmsr(sarg.msr, sarg.eax, sarg.edx)	;
	    	break;
		
	  case WRMSR :
	  
		if(gbuffer!=0){
			wrmsrl(0x8b,0);
			wrmsrl(sarg.msr, gbuffer);
		}
		else{
			//wrmsr(sarg.msr,sarg.eax, sarg.edx);
			__asm__ __volatile__("wrmsr" : /*output*/ : "d"(sarg.edx), "a"(sarg.eax), "c"(sarg.msr), "D"(sarg.edi), "S"(sarg.esi) /*: "%edx", "%eax"*/);
		}
		break;	

	  case WCMD:
		wrmsr(sarg.msr,sarg.eax, sarg.edx);
		break;

	  case IOW:
		__asm__ __volatile__("out %%al, %%dx": /*output*/ : "d"(sarg.io_number), "a"(sarg.data));
		
		break;
	  case IOR:
		__asm__ __volatile__("in %%dx, %%al": /*output*/"=a"(sarg.data) : "d"(sarg.io_number));
		
		break;
	  case MEMR:
//		  printk("size is %d\n",sizeof(sarg.mem_address));
//		  virtual = (unsigned long*)__va(sarg.mem_address);
//		  printk("data is %llx\n",virtual);
////		  printk("data is %llx\n",*virtual);
        sarg.mem_data = * (unsigned long*)__va(sarg.mem_address);
		break;

	  default:  /* redundant, as cmd was checked against MAXNR */
		return -ENOTTY;
	}
	if (copy_to_user((void __user *)arg, &sarg, sizeof(struct scull_arg)))
	return retval;

}

/*
 * Our various sub-devices.
 */
/* Device 0 uses remap_pfn_range */
static struct file_operations simple_remap_ops = {
	.owner   = THIS_MODULE,
	.open    = simple_opend,
	.release = simple_release,
	.unlocked_ioctl = simple_ioctl,
	.compat_ioctl = simple_ioctl,
	.mmap    = simple_remap_mmap,
};


#define MAX_SIMPLE_DEV 2


static struct cdev SimpleDevs[MAX_SIMPLE_DEV];

dev_t dev;
struct class *my_class;
/*
 * Module housekeeping.
 */
static int simple_init(void)
{
	int result;
	 dev = MKDEV(simple_major, 0);
	/* Figure out our device number. */
	if (simple_major)
		result = register_chrdev_region(dev, 2, "simple");
	else {
		result = alloc_chrdev_region(&dev, 0, 2, "simple");
		simple_major = MAJOR(dev);
	}
	if (result < 0) {
		printk(KERN_WARNING "simple: unable to get major %d\n", simple_major);
		return result;
	}
	if (simple_major == 0)
		simple_major = result;
    my_class = class_create(THIS_MODULE,"simple_class"); 
	
	/* Now set up two cdevs. */
	simple_setup_cdev(SimpleDevs, 0, &simple_remap_ops);
	
	device_create(my_class,NULL,dev,NULL,"simple");  
	return 0;
}


static void simple_cleanup(void)
{
	cdev_del(SimpleDevs);
    device_destroy(my_class, dev);  
	class_destroy(my_class);   
	unregister_chrdev_region(MKDEV(simple_major, 0), 2);
}


module_init(simple_init);
module_exit(simple_cleanup);
