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
#include <devices/input.h>

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
	/*
	printf ("\n---------syscall----------\n");
	printf ("rax : %d\n", f->R.rax);
	printf ("rdi : %d\n", f->R.rdi);
	printf ("rsi : %d\n", f->R.rsi);
	printf ("rdx : %d\n", f->R.rdx);
	printf ("----------------------------\n");

	thread_exit ();
	*/

	switch (f->R.rax)
	{
	case SYS_HALT:
	 	/* return void */
		halt ();
	 	break;
	case SYS_EXIT:
	 	/* return void */
	 	exit (f->R.rdi);
	 	break;
	
	case SYS_FORK:
	 	/* return pid_t */
	 	f->R.rax = fork (f->R.rdi, f);
		break;

	case SYS_EXEC:
	 	/* return int */
	 	f->R.rax = exec (f->R.rdi);
	 	break;

	case SYS_WAIT:
	 	/* return int */
	 	f->R.rax = wait(f->R.rdi);
	 	break;
	
	case SYS_CREATE:
	 	/* return bool */
	 	f->R.rax = create(f->R.rdi, f->R.rsi);
	 	break;
	
	case SYS_REMOVE:
	 	/* return bool */
	 	f->R.rax = remove(f->R.rdi);
	 	break;

	case SYS_OPEN:
	 	/* return int */
	 	f->R.rax = open(f->R.rdi);
	 	break;
	
	case SYS_FILESIZE:
	 	/* return int */
	 	f->R.rax = filesize(f->R.rdi);
	 	break;
	
	case SYS_READ:
	 	/* return int */
	 	f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
	 	break;
	
	case SYS_WRITE:
	 	/* return int */
	 	f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
	 	break;
	
	case SYS_SEEK:
	 	/* return void */
	 	seek(f->R.rdi, f->R.rsi);
	 	break;
	
	case SYS_TELL:
	 	/* return unsigned int */
	 	f->R.rax = tell(f->R.rdi);
	 	break;

	case SYS_CLOSE:
	 	/* return void */
	 	close(f->R.rdi);
	 	break;
	
	default:
		thread_exit();
	 	break;
	}	
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *curr = thread_current();
	curr->is_exit = status;
	printf ("%s: exit(%d)\n", curr->name, curr->is_exit);

	thread_exit();
}

pid_t
fork (const char *thread_name, struct intr_frame *f){
	pid_t pid = process_fork(thread_name, f);
	
	return pid;
}

int
exec (const char *cmd_line) {
	char *fn_copy;
	int dst_len = strlen(cmd_line)+1;
	fn_copy = palloc_get_page (PAL_ZERO);
	if (fn_copy == NULL){
		//palloc_free_page(fn_copy);
		exit(-1);
	}
	
	memcpy(fn_copy, cmd_line, dst_len);
	
	if (process_exec (fn_copy) < 0){
		//palloc_free_page(fn_copy);
		return -1;
	}
}

int
wait (pid_t pid) {
	return process_wait(pid);
}

bool
create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	if (!file)
		exit(-1);
	lock_acquire(&filesys_lock);
	int fd;
	check_address(file);
	struct file *curr_file = filesys_open(file);
	if(!curr_file){
		lock_release(&filesys_lock);
		return -1;
	}	

	fd = process_add_file(curr_file);

	if(fd == -1)
		file_close(curr_file);
	lock_release(&filesys_lock);
	return fd;
}

int
filesize (int fd) {
	struct file *curr_file = process_get_file(fd);
	if(!curr_file)
		return -1;
	
	return file_length(curr_file);
}

int
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	lock_acquire(&filesys_lock);
	if(fd == 1){
		lock_release(&filesys_lock);
		return -1;
	}
	char *str_buffer = (char *)buffer;
	int result = 0;
	struct file *curr_file = process_get_file(fd);
	
	if(!curr_file){
		lock_release(&filesys_lock);
		return -1;
	}

	if(fd == 0){
		while(1){
			char input_char = input_getc();
			str_buffer[result] = input_char;
			result++;
			if(input_char == '\0'){
				break;
			}
		}
	} else {
		result = file_read(curr_file, buffer, size);
	}
	

	lock_release(&filesys_lock);
	return result;
}

int
write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	lock_acquire(&filesys_lock);

	int result;
	struct file *curr_file = process_get_file(fd);
	if(fd == 0){
		lock_release(&filesys_lock);
		return -1;
	}

	if(fd == 1){
		putbuf(buffer, size);
		result = size;
	}else {
		if(curr_file == NULL){
			lock_release(&filesys_lock);
			return -1;
		}
		result = file_write(curr_file, buffer, size);
	}
	
	lock_release(&filesys_lock);
	return result;
}
void
seek (int fd, unsigned position) {
	struct file *curr_file = process_get_file(fd);
	file_seek(curr_file, position);
}

unsigned
tell (int fd) {
	struct file *curr_file = process_get_file(fd);
	return file_tell(curr_file);
}

void
close (int fd) {
	if (fd < 2 || fd >= MAX_FDT)
        return NULL;

	struct file *curr_file = process_get_file(fd);
	if(!curr_file)
		return;
	
	thread_current()->fdt[fd] = NULL;
	if (thread_current()->running_file == curr_file)
		thread_current()->running_file = NULL;
	file_close(curr_file);
}
/*

//-----------extra-----------------------------

int
dup2 (int oldfd, int newfd){
	return syscall2 (SYS_DUP2, oldfd, newfd);
}
*/
//-----------extra-----------------------------

void check_address(void *addr){
	if(pml4e_walk(thread_current()->pml4, addr, false) == NULL)
		exit(-1);
}
