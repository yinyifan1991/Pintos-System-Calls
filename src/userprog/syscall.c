
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/*New add*/
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdlib.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "threads/interrupt.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "lib/kernel/list.h"
#include "devices/shutdown.h"
#include "threads/synch.h"

#define MAX_CALL_NUM 13


void halt (void);

void exit (int status);

pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int
read (int fd, void *buffer, unsigned size);

int
write (int fd, const void *buffer, unsigned size);

void
seek (int fd, unsigned position);
unsigned
tell (int fd);
void
close (int fd);


static void syscall_handler (struct intr_frame *);

/*New add for project 2*/

struct file* find_file (int fd);

struct process_file
{
	struct file *file;
	int fd;
	struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /*New add for project 2*/

  int *para = f->esp;
  if (!is_user_vaddr (f->esp))
  {
	
  	exit (-1);
  	return;
  }

  void *ptr = pagedir_get_page (thread_current ()->pagedir, f->esp);
  if (!ptr)
    exit (-1);
  	
  int syscal_index = *(int *)f->esp;
  if (syscal_index < 0 || syscal_index >= MAX_CALL_NUM)
  {
	
  	exit (-1);
  	return;
  }


  switch (*(int *)f->esp)
  {
  	case SYS_HALT:
  	{
		  halt ();
  	}
  	case SYS_EXIT:
  	{
  	  if (!is_user_vaddr(para + 1))
  		{
			  exit (-1);
  		}
  		exit (*(para + 1));
			break;
  	}
  	case SYS_EXEC:
  	{
		  if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
      void *ptr = pagedir_get_page (thread_current ()->pagedir, (para + 1));
      if (!ptr)
        exit (-1);
      
      f->eax = exec (*(para + 1));
      break;  			
  	}
  	case SYS_WAIT:
  	{
  		if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
      f->eax = wait (*(para + 1));
      break;	
  	}
  	case SYS_CREATE:
  	{
		 
      if (!is_user_vaddr(para + 4) || !is_user_vaddr(para + 5))
      {
        exit (-1);
      }
		  
		  void *ptr = pagedir_get_page (thread_current ()->pagedir, (para + 4));
      if (!ptr)
        exit (-1);
      ptr = pagedir_get_page (thread_current ()->pagedir, (para + 5));
      if (!ptr)
        exit (-1);

      f->eax = create (*(para + 4), *(unsigned *)(para + 5));
      break;
		    			
  	}
  	case SYS_REMOVE:
  	{
  	  if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
      f->eax = remove (*(para + 1));
      break;
  	}
  	case SYS_OPEN:
  	{
		  
  		if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
		  void *ptr = pagedir_get_page (thread_current ()->pagedir, (f->esp + 4));
       if (!ptr)
         exit (-1);
		  
        f->eax = open (*(para + 1));
        break;
  	}
  	case SYS_FILESIZE:
  	{
		  if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
      f->eax = filesize (*(para + 1));
      break;  			
  	}
  	case SYS_READ:
  	{
  		if (!is_user_vaddr(para + 5) || !is_user_vaddr(para + 6) || !is_user_vaddr(para + 7))
      {
        exit (-1);
      }
      void *ptr = pagedir_get_page (thread_current ()->pagedir, (para + 5));
      if (!ptr)
          exit (-1);
      ptr = pagedir_get_page (thread_current ()->pagedir, (para + 6));
      if (!ptr)
        exit (-1);
      ptr = pagedir_get_page (thread_current ()->pagedir, (para + 7));
      if (!ptr)
        exit (-1);
      f->eax = read (*(int *)(para + 5), *(int *)(para + 6), *(unsigned *)(para + 7));
      break;  
  	}
  	case SYS_WRITE:
  	{

  		if (!is_user_vaddr(para + 5) || !is_user_vaddr(para + 6) || !is_user_vaddr(para + 7))
  		{
  			exit (-1);
  		}
			void *ptr = pagedir_get_page (thread_current ()->pagedir, (para + 5));
      if (!ptr)
      	exit (-1);
      ptr = pagedir_get_page (thread_current ()->pagedir, (para + 6));
      if (!ptr)
        exit (-1);
      ptr = pagedir_get_page (thread_current ()->pagedir, (para + 7));
      if (!ptr)
        exit (-1);
  		f->eax = write (*(int *)(f->esp + 20), *(int *)(f->esp+24), *(unsigned *)(f->esp + 28));
  		break;	
  	}
  	case SYS_SEEK:
  	{
  		if (!is_user_vaddr(para + 4) || !is_user_vaddr(para + 5))
      {
        exit (-1);
      }
      seek (*(para + 4), *(unsigned *)(para + 5));
      break;
  	}
  	case SYS_TELL:
  	{
		  if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
      f->eax = tell (*(para + 1));
      break;  			
  	}
  	case SYS_CLOSE:
  	{

		  if (!is_user_vaddr(para + 1))
      {
        exit (-1);
      }
		  void *ptr = pagedir_get_page (thread_current ()->pagedir, (f->esp + 4));
      if (!ptr)
        exit (-1);
      close (*(para + 1));
      break;  			

  	}
  }

}

void halt (void)
{
  shutdown_power_off ();
}


void exit (int status)
{

  struct thread *cur = thread_current ();
  cur->sys_status = status;
  thread_exit ();

}


pid_t exec (const char *cmd_line)
{
  if (!is_user_vaddr(cmd_line))
  {
    exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, cmd_line);
  if (!ptr)
    exit (-1);
  return process_execute (cmd_line);
}


int wait (pid_t pid)
{
  return process_wait (pid);
}


bool create (const char *file, unsigned initial_size)
{

  bool success;
  if (!is_user_vaddr(file) || !is_user_vaddr (file + initial_size))
  {
    exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, file);
  if (!ptr)
    exit (-1);
  ptr = pagedir_get_page (thread_current ()->pagedir, (file + initial_size));
  if (!ptr)
    exit (-1);
  if (file == NULL || initial_size < 0)
  {
    exit (-1);
  }
  else
  {
    success = filesys_create (file, initial_size);
    return success;
  }

}

bool remove (const char *file)
{
  if (!is_user_vaddr(file))
  {
    exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, file);
    if (!ptr)
      exit (-1);
  bool success;
  if (file == NULL)
  {
    exit (-1);
  }
  else
  {
    success = filesys_remove (file);
    return success;
  }

}

int open (const char *file)
{
  if (!is_user_vaddr(file))
  {
    exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, file);
  if (!ptr)
    exit (-1);
  if (file == NULL)
  {
    return -1;
  }
  else
  {
  struct file *f = filesys_open (file);
  if (!f)
  {
    return -1;
  }
  int fd = add_file (f);
  return fd;
  }
}

int filesize (int fd)
{
  struct file *f = find_file (fd);
  if (!f)
  {
    return -1;
  }
  int size_byte = file_length (f);
  return size_byte;
}

int
read (int fd, void *buffer, unsigned size)
{
  int i;
  int ret = -1;
  uint8_t *buf = (uint8_t *)buffer;

  if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + size))
  {
    exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, buffer);
  if (!ptr)
    exit (-1);
  ptr = pagedir_get_page (thread_current ()->pagedir, (buffer + size));
  if (!ptr)
    exit (-1);

  if (fd == STDOUT_FILENO)
  {
    ret = -1;
  }
  else if (fd == STDIN_FILENO)
  {
    for (i = 0;i < size;i++)
    {
      buf[i] = input_getc ();
    }
    ret = size;
  }
  else
  {
    struct file *file = find_file (fd);
    if (!file)
    {
      return -1;
    }
    int ret_byte = file_read (file, buffer,size);
    ret = ret_byte;
  }
  return ret;

}


int
write (int fd, const void *buffer, unsigned size)
{
  int ret = -1;

  if (!is_user_vaddr ((int *)buffer) || !is_user_vaddr (buffer + size))
  {
  	exit (-1);
  }
  void *ptr = pagedir_get_page (thread_current ()->pagedir, buffer);
  if (!ptr)
    exit (-1);
  ptr = pagedir_get_page (thread_current ()->pagedir, (buffer + size));
  if (!ptr)
    exit (-1);
  if (fd == STDIN_FILENO)
  {
  	ret = -1;
	return ret;
  }

  else if (fd == STDOUT_FILENO)
  {
  	putbuf (buffer, size);
  	ret = size;
	  return ret;
  }
  else
  {
    struct file *file = find_file (fd);

    if (!file)
    {
      return -1;
    }

    int input_byte = file_write (file, buffer, size);
    return input_byte;
  }

}


void
seek (int fd, unsigned position) 
{
  struct file *file = find_file (fd);
  if (!file)
  {
    return;
  }
  file_seek (file, position);  
}

unsigned
tell (int fd) 
{
  struct file *file = find_file (fd);
  if(!file)
  {
    return -1;
  }
  off_t pos_byte = file_tell (file);
  return pos_byte;  
}

void
close (int fd)
{

  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->file_list);e != list_end (&cur->file_list);e = list_next (e))
  {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (!pf)
    {
      return;
    }
    else if (pf->fd == fd || fd == -1)
    {
      file_close (pf->file);
      list_remove (&pf->elem);
      free (pf);

      if (fd != -1)
      {
        return;
      }

    }
  }   

}


struct file* find_file (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;

  for (e = list_begin (&cur->file_list);e != list_end (&cur->file_list);e = list_next (e))
  {
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (pf->fd == fd)
       return pf->file;
  }
  return NULL;
}

int add_file (struct file *file)
{
  struct process_file *pf = malloc (sizeof (struct process_file));
  if (pf == NULL)
  {
    return -1;
  }
  pf->file = file;
  pf->fd = thread_current ()->fd;
  thread_current ()->fd++;
  list_push_back (&thread_current ()->file_list, &pf->elem);
  return pf->fd;
}
