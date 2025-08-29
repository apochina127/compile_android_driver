#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/tty.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <linux/mmu_context.h>
#include <asm/page.h>
#include <asm/pgtable.h>

extern struct mm_struct *get_task_mm(struct task_struct *task);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61))
extern void mmput(struct mm_struct *);

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
	{
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#else
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{

	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
	{
		return 0;
	}
	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
	{
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
	{
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte))
	{
		return 0;
	}
	if (!pte_present(*pte))
	{
		return 0;
	}
	// 页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	// 页内偏移
	page_offset = va & (PAGE_SIZE - 1);

	return page_addr + page_offset;
}
#endif

#ifdef ARCH_HAS_VALID_PHYS_ADDR_RANGE
static size_t get_high_memory(void)
{
	struct sysinfo meminfo;
	si_meminfo(&meminfo);
	return (meminfo.totalram * (meminfo.mem_unit / 1024)) << PAGE_SHIFT;
}
#define valid_phys_addr_range(addr, count) (addr + count <= get_high_memory())
#else
#define valid_phys_addr_range(addr, count) true
#endif


bool read_physical_address(struct mm_struct *mm,phys_addr_t pa,uintptr_t addr,void *buffer, size_t size)
{
    bool result = false;
    struct mm_struct *old_mm;
    struct mm_struct *old_mm1;
    unsigned long flags;
    void* tempmemory = kmalloc(size,GFP_KERNEL);
    if(tempmemory == NULL)
    {
        return false;
    }
    memset(tempmemory,0,size);
	if (!pfn_valid(__phys_to_pfn(pa)))
	{
        kfree(tempmemory);
		return false;
	}
	if (!valid_phys_addr_range(pa, size))
	{
        kfree(tempmemory);
		return false;
	}
    local_irq_save(flags);
    phys_addr_t pgd_phys = virt_to_phys(mm->pgd);
    old_mm = current->active_mm;
    old_mm1 = current->mm;
    current->active_mm = mm;
    current->mm=mm;
    asm volatile(
        "msr ttbr0_el1, %0\n"
        "isb\n"
        : : "r" (pgd_phys)
    );
    asm volatile(
        "dsb ishst\n"          
        "tlbi vmalle1is\n"     
        "dsb ish\n"            
        "isb\n"                
        : : : "memory"
    );
    if(copy_from_user(tempmemory,(void __user *)addr,size) == 0)
    {
        if(copy_to_user(buffer,tempmemory,size) == 0)
        {
            result = true;
        }
    }
    pgd_phys = virt_to_phys(old_mm->pgd);
    current->mm = old_mm1;
    current->active_mm = old_mm;
        asm volatile(
        "msr ttbr0_el1, %0\n"
        "isb\n"
        : : "r" (pgd_phys)
    );
    asm volatile(
        "dsb ishst\n"          
        "tlbi vmalle1is\n"     
        "dsb ish\n"            
        "isb\n"                
        : : : "memory"
    );
    local_irq_restore(flags);
    kfree(tempmemory);
	return result;
}


bool read_process_memory(
	pid_t pid,
	uintptr_t addr,
	void *buffer,
	size_t size)
{

	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_struct;
	phys_addr_t pa;
	bool result = false;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
	{
		return false;
	}
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
	{
		return false;
	}
	mm = get_task_mm(task);
	if (!mm)
	{
		return false;
	}

	pa = translate_linear_address(mm, addr);
	if (pa)
	{
		result = read_physical_address(mm,pa,addr,buffer,size);
	}
	else
	{
		if (find_vma(mm, addr))
		{
			if (clear_user(buffer, size) == 0)
			{
				result = true;
			}
		}
	}

	mmput(mm);
	return result;
}

