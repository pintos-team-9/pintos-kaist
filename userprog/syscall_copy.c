#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "userprog/process.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
	printf ("\n---------syscall----------\n");
	printf ("rax : %d\n", f->R.rax);
	printf ("rdi : %d\n", f->R.rdi);
	printf ("rsi : %d\n", f->R.rsi);
	printf ("rdx : %d\n", f->R.rdx);
	printf ("----------------------------\n");

	thread_exit ();
	// switch (f->R.rax)
	// {
	// case SYS_HALT:
	// 	/* return void */
	// 	halt ();
	// 	break;
	// case SYS_EXIT:
	// 	/* return void */
	// 	exit (f->R.rdi);
	// 	break;
	
	// case SYS_FORK:
	// 	/* return pid_t */
	// 	f->R.rax = fork (f->R.rdi, f);
	// 	break;
	
	// case SYS_EXEC:
	// 	/* return int */
	// 	f->R.rax = exec (f->R.rdi);
	// 	break;
	
	// case SYS_WAIT:
	// 	/* return int */
	// 	wait(f->R.rdi);
	// 	break;
	
	// case SYS_CREATE:
	// 	/* return bool */
	// 	f->R.rax = create(f->R.rdi, f->R.rsi);
	// 	break;
	
	// case SYS_REMOVE:
	// 	/* return bool */
	// 	f->R.rax = remove(f->R.rdi);
	// 	break;

	// case SYS_OPEN:
	// 	/* return int */
	// 	f->R.rax = open(f->R.rdi);
	// 	break;
	
	// case SYS_FILESIZE:
	// 	/* return int */
	// 	f->R.rax = filesize(f->R.rdi);
	// 	break;
	
	// case SYS_READ:
	// 	/* return int */
	// 	f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
	// 	break;
	
	// case SYS_WRITE:
	// 	/* return int */
	// 	f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
	// 	break;
	
	// case SYS_SEEK:
	// 	/* return void */
	// 	seek(f->R.rdi, f->R.rsi);
	// 	break;
	
	// case SYS_TELL:
	// 	/* return unsigned int */
	// 	f->R.rax = tell(f->R.rdi);
	// 	break;

	// case SYS_CLOSE:
	// 	/* return void */
	// 	close(f->R.rdi);
	// 	break;
	
	// default:
	// 	break;
	// }
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *curr = thread_current();
	//curr->is_exit = status;
	thread_exit();
}

pid_t
fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}

int
exec (const char *cmd_line) {
	char *fn_copy;
	int dst_len = strlen(cmd_line)+1;
	fn_copy = palloc_get_page (PAL_ZERO);
	if (fn_copy == NULL)
		exit(-1);

	memcpy(fn_copy, cmd_line, dst_len);

	if (process_exec (fn_copy) < 0)
		exit(-1);
}

int
wait (pid_t pid) {
	process_wait(pid);
}

bool
create (const char *file, unsigned initial_size) {
	printf("\n\nfock\n\n");
	check_address(file);
	return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}
//-----------extra-----------------------------
/*
int
open (const char *file) {
	return syscall1 (SYS_OPEN, file);
}

int
filesize (int fd) {
	return syscall1 (SYS_FILESIZE, fd);
}

int
read (int fd, void *buffer, unsigned size) {
	return syscall3 (SYS_READ, fd, buffer, size);
}
*/
int
write (int fd, const void *buffer, unsigned size) {
	if(fd == 1)
		printf("%s", buffer);
	return 0;
}
/*
void
seek (int fd, unsigned position) {
	syscall2 (SYS_SEEK, fd, position);
}

unsigned
tell (int fd) {
	return syscall1 (SYS_TELL, fd);
}

void
close (int fd) {
	syscall1 (SYS_CLOSE, fd);
}

int
dup2 (int oldfd, int newfd){
	return syscall2 (SYS_DUP2, oldfd, newfd);
}
*/

void check_address(void *addr){
	if(!is_user_vaddr(addr))
		exit(-1);
}
