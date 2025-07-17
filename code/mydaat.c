#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/highuid.h>
#include <linux/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <linux/delay.h>
#include "memory.h"
#include "comm.h"
#include "process.h"
#include "mydaat.h"
#include "kprobe_all.h"
#include "mmuhack.h"
#include "kallsyms.h"



typedef long (*syscall_fn_t)(const struct pt_regs* regs);
static syscall_fn_t prototype_ioctl;

asmlinkage long custom_ioctl(const struct pt_regs* regs) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    //unsigned int fd = regs->regs[0];
    unsigned int cmd = regs->regs[1];
    unsigned long arg = regs->regs[2];
    static char name[0x100] = {0};
    if (cmd == OP_MODULE_BASE) {
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
		{
			return -1;
		}
		mb.base = get_module_base(mb.pid, name);
		if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
		{
			return -1;
		}
        return 0;
    }

    if(cmd == OP_READ_MEM){
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
		{
			return -1;
		}
		if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
		{
			return -1;
		}
        printk("接受指令正在读内存");
        return 0;
    }
    
    return prototype_ioctl(regs);
}



static int __init CBHD_init(void) {
    int ret;
    //pmd_t pmd_backup[100] = {0, };
    printk(KERN_INFO "[CBHD] hello kernel!\n");

    if(kprobe_init() != 0) {
        printk(KERN_ERR "[CBHD] kprobe_init failed\n");
        return -1;
    }

    if(init_memhack() != 0) {
        printk(KERN_ERR "[CBHD] init_memhack failed\n");
        return -1;
    }

    ret = unprotect_rodata_memory(PRD_MODE_V3, __NR_ioctl);
    if (ret != 0) {
        printk(KERN_ERR "[CBHD] unprotect_rodata_memory failed\n");
        return -1;
    }

    prototype_ioctl = (syscall_fn_t) find_syscall_table()[__NR_ioctl];
    printk(KERN_INFO "[CBHD] original mkdirat: 0x%lx\n", (unsigned long) prototype_ioctl);

    find_syscall_table()[__NR_ioctl] = (unsigned long)custom_ioctl;

    ret = protect_rodata_memory(PRD_MODE_V3, __NR_ioctl);
    if (ret != 0) {
        printk(KERN_ERR "[CBHD] protect_rodata_memory failed\n");
        return -1;
    }
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;
}

static void __exit CBHD_exit(void) {
    int ret;
    printk(KERN_INFO "[CBHD] goodbye kernel!\n");

    kprobe_exit();

    ret = unprotect_rodata_memory(PRD_MODE_V3, __NR_ioctl);
    if (ret != 0) {
        printk(KERN_ERR "[CBHD] unprotect_rodata_memory failed\n");
    }
    find_syscall_table()[__NR_ioctl] = (unsigned long)prototype_ioctl;
    ret = protect_rodata_memory(PRD_MODE_V3, __NR_ioctl);
    if (ret != 0) {
        printk(KERN_ERR "[CBHD] protect_rodata_memory failed\n");
    }
}

module_init(CBHD_init);
module_exit(CBHD_exit);

MODULE_AUTHOR("CubeByte");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
