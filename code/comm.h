typedef struct _COPY_MEMORY
{
	pid_t pid;
	int unused;
	uintptr_t addr;
	int unused1;
	void *buffer;
	int unused2;
	size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE
{
	pid_t pid;
	int unused;
	char *name;
	int unused1;
	uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

enum OPERATIONS
{
	OP_INIT_KEY = 11,
	OP_READ_MEM = 66,
	OP_MODULE_BASE = 99,
};