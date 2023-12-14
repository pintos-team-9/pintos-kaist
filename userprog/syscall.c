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
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void sys_halt (void) NO_RETURN;
void sys_exit (int status) NO_RETURN;
int sys_filesize (int fd);
bool sys_create (const char *file, unsigned initial_size);
int sys_open (const char *file);
bool sys_remove (const char *file);
int sys_read (int fd, void *buffer, unsigned size);
void check_address(void *addr);
pid_t sys_fork (const char *thread_name, struct intr_frame *f);
int sys_wait (pid_t pid);
void sys_seek (int fd, unsigned position);
int sys_exec (const char *file);
int sys_write (int fd, const void *buffer, unsigned size);

unsigned sys_tell (int fd);

struct lock filesys_lock; //자물쇠
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
	lock_init(&filesys_lock); //세마를 1로 설정.

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
	switch (f->R.rax)
	{
	case SYS_HALT:
	 	/* return void */
		sys_halt ();
	 	break;
	case SYS_EXIT:
	 	/* return void */
	 	sys_exit (f->R.rdi);
	 	break;
	
	case SYS_FORK:
	 	/* return pid_t */
	 	f->R.rax = sys_fork (f->R.rdi, f);
		break;

	case SYS_EXEC:
	 	/* return int */
	 	f->R.rax = sys_exec (f->R.rdi);
	 	break;

	case SYS_WAIT:
	 	/* return int */
	 	f->R.rax = sys_wait(f->R.rdi);
	 	break;
	
	case SYS_CREATE:
	 	/* return bool */
	 	f->R.rax = sys_create(f->R.rdi, f->R.rsi);
	 	break;
	
	case SYS_REMOVE:
	 	/* return bool */
	 	f->R.rax = sys_remove(f->R.rdi);
	 	break;

	case SYS_OPEN:
	 	/* return int */
	 	f->R.rax = sys_open(f->R.rdi);
	 	break;
	
	case SYS_FILESIZE:
	 	/* return int */
	 	f->R.rax = sys_filesize(f->R.rdi);
	 	break;
	
	case SYS_READ:
	 	/* return int */
	 	f->R.rax = sys_read(f->R.rdi, f->R.rsi, f->R.rdx);
	 	break;
	
	case SYS_WRITE:
	 	/* return int */
	 	f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
	 	break;
	
	case SYS_SEEK:
	 	/* return void */
	 	sys_seek(f->R.rdi, f->R.rsi);
	 	break;
	
	case SYS_TELL:
	 	/* return unsigned int */
	 	f->R.rax = sys_tell(f->R.rdi);
	 	break;

	case SYS_CLOSE:
	 	/* return void */
	 	sys_close(f->R.rdi);
	 	break;
	
	default:
		thread_exit();
	 	break;
	}
}

void
sys_halt (void) {
	power_off();
}

void
sys_exit(int status){
	struct thread *now_thread = thread_current();
	now_thread->exit_status = status;


	printf ("%s: exit(%d)\n", now_thread->name, now_thread->exit_status);
	thread_exit();
}

int sys_filesize (int fd) {
	struct thread *now_thread = thread_current();
	if(fd > 2 && fd < 64 && now_thread->fdt[fd] != NULL){
		int size = file_length(now_thread->fdt[fd]); 
		return size;
	}
	return -1;
}

bool sys_create (const char *file, unsigned initial_size) {
	check_address(file); //kernel 영역에서만 만들면 안되고 user영역에서 file을 만들어야함!
	return filesys_create(file, initial_size);
}

int sys_open (const char *file) {
	check_address(file);
	if(file == NULL)
		return -1;
	int fd;
	struct file *now_file = filesys_open(file);
	if(now_file == NULL){
		return -1;
	}
	//현재스레드 이름과 file이 동일한지 비교해서(동일하면 0) now_file 쓰기 권한 거부
	if(strcmp(thread_name(), file) == 0) 
		file_deny_write(now_file);
	fd = process_add_file(now_file);
	return fd;
}

bool sys_remove (const char *file) {
	return filesys_remove(file);
}

int sys_read (int fd, void *buffer, unsigned size) {

	struct thread *now_thread = thread_current();
	check_address(buffer);
	lock_acquire(&filesys_lock);
	if(fd == 0){
		lock_release(&filesys_lock);
		return input_getc();
	}
	if(fd < 3 || fd >= 64 || now_thread->fdt[fd] == NULL || !buffer){
		lock_release(&filesys_lock);
		return -1;
	}
	struct file *f = now_thread->fdt[fd];
	int byte_read = file_read(f, buffer, size);
	//printf("\n read -------------%d\n", byte_read);
	lock_release(&filesys_lock);
	return byte_read;
}

int sys_write (int fd, const void *buffer, unsigned size) {
	int byte_written;
	check_address(buffer);
	lock_acquire(&filesys_lock);
	if(fd == 1){
		//putbuf(buffer, size);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}
	struct thread *now_thread = thread_current();

	if(fd <3 || fd>= 64 || now_thread->fdt[fd] ==NULL){
		lock_release(&filesys_lock);
		return -1;
	}
	struct file *f = now_thread->fdt[fd];
	if(f == NULL){
		lock_release(&filesys_lock);
		return -1;
	}
	byte_written = file_write(f, buffer, size);
	lock_release(&filesys_lock);
	return byte_written;
}

void
sys_seek (int fd, unsigned position) {
	struct thread *now_thread = thread_current();
	struct file *f = now_thread->fdt[fd];
	/*
	if(fd <3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		return -1;
	*/
	file_seek(f, position);
}

unsigned sys_tell (int fd) {
	struct thread *now_thread = thread_current();
	struct file *f = now_thread->fdt[fd];
	if(fd <3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		return -1;
	return file_tell(f);
}

void sys_close (int fd) {
	struct thread *now_thread = thread_current();
	if(fd < 3 || fd>= 64 || now_thread->fdt[fd] == NULL)
		sys_exit(-1);
	struct file *f = now_thread->fdt[fd];
	now_thread->fdt[fd] = NULL;
	file_close(f);

}

pid_t sys_fork (const char *thread_name, struct intr_frame *f){
	pid_t pid = process_fork(thread_name, f);
	return pid;
}

int sys_wait (pid_t pid) {
	int pid_wait = process_wait(pid);
	return pid_wait;
}


int sys_exec (const char *file){
	check_address(file);
	int file_size = strlen(file);
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if(!fn_copy)
		return -1;
	
	//strlcpy(fn_copy, cmd_line, file_size)
	memcpy(fn_copy, file, file_size);

	if(process_exec(fn_copy) < 0)
		sys_exit(-1);
}



/*-----address check-----*/
void check_address(void *addr){
	if(pml4e_walk(thread_current()->pml4, addr, false) == NULL)
		sys_exit(-1);
}
