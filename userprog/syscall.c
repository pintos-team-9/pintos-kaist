#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "lib/kernel/console.h"
#include "devices/input.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void exit(int status);
void halt(void); 
int filesize (int fd);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
bool remove (const char *file);
int read (int fd, void *buffer, unsigned size);
void check_address(void *addr);
pid_t fork (const char *thread_name, struct intr_frame *f);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	//printf("syscall number: %d\n",f->R.rax);
	switch(f->R.rax){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			remove(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			//printf("%s",f->R.rsi);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;

	}

}

void
halt (void) {
	power_off();
}

void
exit(int status){
	struct thread *now_thread = thread_current();
	now_thread->exit_status = status;
	thread_exit();
}

int
filesize (int fd) {
	struct thread *now_thread = thread_current();
	if(fd > 2 && fd < 64 && now_thread->fdt[fd] != NULL){
		int size = file_length(now_thread->fdt[fd]); 
		return size;
	}
}

bool
create (const char *file, unsigned initial_size) {
	check_address(file); //kernel 영역에서만 만들면 안되고 user영역에서 file을 만들어야함!
	return filesys_create(file, initial_size);
}

int
open (const char *file) {
	check_address(file);
	if(file == NULL)
		return -1;
	int fd;
	struct file *now_file = filesys_open(file);
	if(now_file == NULL){
		return -1;
	}
	fd = process_add_file(now_file);
	return fd;
}

bool
remove (const char *file) {
	return filesys_remove(file);
}

int
read (int fd, void *buffer, unsigned size) {
	struct thread *now_thread = thread_current();
	check_address(buffer);
	if(fd == 0){
		return input_getc();
	}
	if(fd < 3 || fd >= 64 || now_thread->fdt[fd] == NULL || !buffer){
		return -1;
	}
	struct file *f = now_thread->fdt[fd];
	int byte_read = file_read(f, buffer, size);
	//printf("\n read -------------%d\n", byte_read);
	return byte_read;
}

int
write (int fd, const void *buffer, unsigned size) {
	int byte_written;
	check_address(buffer);
	if(fd == 1){
		//putbuf(buffer, size);
		printf("%s", buffer);
		return size;
	}
	struct thread *now_thread = thread_current();

	if(fd <3 || fd>= 64 || now_thread->fdt[fd] ==NULL)
		return -1;
	struct file *f = now_thread->fdt[fd];
	if(f == NULL)
		return -1;

	byte_written = file_write(f, buffer, size);
	return byte_written;
}

void
seek (int fd, unsigned position) {
	struct thread *now_thread = thread_current();
	struct file *f = now_thread->fdt[fd];
	if(fd <3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		return -1;
	file_seek(f, position);
}

unsigned
tell (int fd) {
	struct thread *now_thread = thread_current();
	struct file *f = now_thread->fdt[fd];
	if(fd <3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		return -1;
	return file_tell(f);
}

void close (int fd) {
	struct thread *now_thread = thread_current();
	if(fd < 3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		exit(-1);
	struct file *f = now_thread->fdt[fd];
	file_close(f);
	now_thread->fdt[fd] = NULL;
}

pid_t fork (const char *thread_name, struct intr_frame *f){
	pid_t pid = process_fork(thread_name, f);
	return pid;
}

/*-----address check-----*/
void check_address(void *addr){
	if(pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}
