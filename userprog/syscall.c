#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"
// #include "lib/user/syscall.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "lib/string.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address (void *addr);

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct lock filesys_lock;

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
	lock_init(&filesys_lock);
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
	// check_address(f->rsp);

	// printf("%d", f->R.rax);
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			exit(f->R.rdi);	// status
			break;
		
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);	// thread_name, f
			break;
		
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi); // cmd_line
			break;
		
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);	// pid
			break;
		
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);	// file, initial_size
			break;
		
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		
		case SYS_CLOSE:
			close(f->R.rdi);
			break;

		default:
			thread_exit();
			break;
	}
}

void check_address (void *addr) {
	// 주소 값이 유저 영역 주소 값인지 확인
	// 1. 널 포인터거나 2. 제대로 매핑이 되지 않은 포인터거나 3. 커널 가상 주소 영역이이면 프로세스 종료
	if ( addr == NULL || !is_user_vaddr(addr) || !pml4_get_page(thread_current()->pml4, addr) ) {
	// if ( !pml4_get_page(thread_current()->pml4, addr) ) {
		exit(-1);
	}
}

void halt (void) {
	power_off();
}

void exit (int status) {
	// wait에서 사용할 기존의 status 저장
	struct thread *curr = thread_current();
	curr->exit_status = status;
	
	printf ("%s: exit(%d)\n", thread_name(), thread_current()->exit_status);
	thread_exit();
}

pid_t fork (const char *thread_name, struct intr_frame *f) {
	return process_fork(thread_name, f);
}

int exec (const char *cmd_line) {
	check_address(cmd_line);
	int file_size = strlen(cmd_line)+1;
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if ( fn_copy == NULL ) {
		return -1;
	}

	strlcpy(fn_copy, cmd_line, file_size);	// file_size - 1 개의 문자 복사
	// memcpy(fn_copy, cmd_line, file_size);

	if ( process_exec(fn_copy) < 0 ) {
		exit(-1);
	}
}

int wait (pid_t pid) {
	
	return process_wait(pid);
	// return pid_wait;
}

bool create (const char *file, unsigned initial_size) {
	check_address(file);

	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	return filesys_remove(file);
}

int open (const char *file) {
	check_address(file);

	if ( !file || !filesys_open(file)) {
		return -1;
	}
	
	struct file *now_file = filesys_open(file);

	if ( strcmp(thread_name(), file) == 0 )
		file_deny_write(now_file);

	int fd = process_add_file(now_file);

	return fd;
}

int filesize (int fd) {
	struct thread *now_thread = thread_current();

	if ( fd < 3 || fd >= 64 || !now_thread->fdt[fd] ) {
		return -1;
	}

	return file_length(now_thread->fdt[fd]);		
}

int read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	
	lock_acquire(&filesys_lock);

	struct file *f = process_get_file(fd);

	if (!f || !buffer) {
		lock_release(&filesys_lock);
		return -1;
	}

	if ( fd == 0 ) {
		lock_release(&filesys_lock);
		return input_getc();
	}

	int byte = file_read(f, buffer, size);

	lock_release(&filesys_lock);

	return byte;
}

int write (int fd, const void *buffer, unsigned size) {
	
	struct file *f = process_get_file(fd);
	check_address(buffer);
	lock_acquire(&filesys_lock);

	if ( fd == 1 ) {
		putbuf(buffer, size);
		// printf("%s", buffer);
		lock_release(&filesys_lock);
		return sizeof(buffer);
	}

	if (!f || !buffer) {
		lock_release(&filesys_lock);
		return -1;
	}

	int byte = file_write(f, buffer, size);

	lock_release(&filesys_lock);
	return byte;
}

void seek (int fd, unsigned position) {
	struct file *f = process_get_file(fd);

	if (!f) {
		exit(-1);
	}

	file_seek(f, position);
}

unsigned tell (int fd) {
	struct file *f = process_get_file(fd);

	if (!f) {
		return -1;
	}

	return file_tell(f);
}

void close (int fd) {
	struct file *f = process_get_file(fd);
	// check_address(f);

	if (!f) {
		exit(-1);
	}
	
	file_close(f);
	
	// twice
	thread_current()->fdt[fd] = NULL;
}
