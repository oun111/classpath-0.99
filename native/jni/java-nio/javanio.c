/* javanio.c -- implementations of functions in javanio.h.
   Copyright (C) 2006  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */


/*
 * Note, because these functions are trivial, and should be inlined,
 * we include this file in the header, and do not compile it.
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/uio.h>


// yzhou
ssize_t my_jvm_nio_hook_read(int fd, char *buf, int len)
{
  struct my_jvm_hook_s {
    int (*hook_accept) (void);
    int (*hook_listen)(int);
    int (*hook_read)(int,char*,size_t*);
    int (*hook_write)(int,char*,size_t);
  } ;

  extern int get_module_id(const char *mod_name) ;
  extern void* get_module_extra(int mod_id) ;

  int modid = get_module_id("my_jvm");
  struct my_jvm_hook_s *pe = get_module_extra(modid);
  ssize_t result = 0L;


  if (pe) {
    size_t ret = len;


    result= pe->hook_read(fd,buf,&ret);
    errno = EAGAIN ;
    //printf("%s: result: %zu\n",__func__,result);

    // fd 's NOT hooked, turn to original read call
    if (result==-2) 
      result = read (fd, buf, len);

    // yzhou
    if (result>0)
      printf("%s: fd %d rx: %s, size: %zu, errno: %d\n",__func__,
          fd,buf,result,errno);
  }
  else {
    result= -1;
    errno = ENOENT ;
  }

  return result ;
}


ssize_t my_jvm_nio_hook_write(int fd, char *buf, size_t len)
{
  struct my_jvm_hook_s {
    int (*hook_accept) (void);
    int (*hook_listen)(int);
    int (*hook_read)(int,char*,size_t*);
    int (*hook_write)(int,char*,size_t);
  } ;

  extern int get_module_id(const char *mod_name) ;
  extern void* get_module_extra(int mod_id) ;

  int modid = get_module_id("my_jvm");
  struct my_jvm_hook_s *pe = get_module_extra(modid);
  ssize_t result = 0L ;


  if (pe) {
    size_t ret = len;


    result= pe->hook_write(fd,buf, ret);
    errno = EAGAIN ;
    //printf("%s: result: %zu\n",__func__,result);

    // fd 's NOT hooked, turn to original read call
    if (result==-2) 
      result = write (fd, buf, len);

    // yzhou
    if (result>0)
      printf("%s: tx: %s, size: %zu\n",__func__,buf,result);
  }
  else {
    result= -1;
    errno = ENOENT ;
  }

  return result ;
}

int my_jvm_nio_hook_accept(void)
{
  struct my_jvm_hook_s {
    int (*hook_accept) (void);
    int (*hook_listen)(int);
    int (*hook_read)(int,char*,size_t*);
    int (*hook_write)(int,char*,size_t);
  } ;

  extern int get_module_id(const char *mod_name) ;
  extern void* get_module_extra(int mod_id) ;

  int modid = get_module_id("my_jvm"), ret = -1;
  struct my_jvm_hook_s *pe = get_module_extra(modid);


  if (pe) {
    ret   = pe->hook_accept();
    errno = EAGAIN ;
  }
  else {
    ret   = -1;
    errno = ENOENT ;
  }

  return ret ;
}

CPNIO_EXPORT ssize_t
cpnio_read (int fd, void *buf, size_t nbytes)
{
  //return read (fd, buf, nbytes);
  return my_jvm_nio_hook_read(fd,buf,nbytes);
}

CPNIO_EXPORT ssize_t
cpnio_readv (int fd, const struct iovec *iov, int iovcnt)
{
  return readv (fd, iov, iovcnt);
}

CPNIO_EXPORT ssize_t
cpnio_write (int fd, const void *buf, size_t nbytes)
{
  //return write (fd, buf, nbytes);
  return my_jvm_nio_hook_write(fd,(char*)buf,nbytes) ;
}

CPNIO_EXPORT ssize_t
cpnio_writev (int fd, const struct iovec *iov, size_t iovcnt)
{
  return writev (fd, iov, iovcnt);
}

CPNIO_EXPORT int
cpnio_socket (int domain, int type, int protocol)
{
  return socket (domain, type, protocol);
}

CPNIO_EXPORT int
cpnio_connect (int fd, const struct sockaddr *addr, socklen_t addrlen)
{
  return connect (fd, addr, addrlen);
}

CPNIO_EXPORT int
cpnio_accept (int fd, struct sockaddr *addr, socklen_t *addrlen)
{
  // yzhou
#if 0
  fd_set rset;
  struct timeval tv;
  socklen_t tvlen = sizeof(tv);
  int ret;

  tv.tv_sec = 0;
  tv.tv_usec = 0;
  getsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tvlen);
  if (tv.tv_sec > 0 || tv.tv_usec > 0)
    {
      FD_ZERO(&rset);
      FD_SET(fd,&rset);
      ret = select (fd+1,&rset,NULL,NULL,&tv);
      if (ret == 0)
        {
          errno = EAGAIN;
          return -1;
        }
    }
  return accept (fd, addr, addrlen);
#else
  (void) fd;
  (void) addr;
  (void) addrlen;

  return my_jvm_nio_hook_accept();
#endif
}

CPNIO_EXPORT ssize_t
cpnio_sendto (int fd, const void *msg, size_t len, int flags,
              const struct sockaddr *to, socklen_t tolen)
{
  return sendto (fd, msg, len, flags, to, tolen);
}

CPNIO_EXPORT ssize_t
cpnio_recvfrom (int fd, void *buf, size_t len, int flags,
                struct sockaddr *from, socklen_t *fromlen)
{
  return recvfrom (fd, buf, len, flags, from, fromlen);
}

CPNIO_EXPORT int
cpnio_fcntl (int fd, int cmd, long arg)
{
#ifdef HAVE_FCNTL
  return fcntl (fd, cmd, arg);
#else
  errno = ENOSUP;
  return -1;
#endif /* HAVE_FCNTL */
}

CPNIO_EXPORT int
cpnio_select (int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *excepfds, struct timeval *timeo)
{
  return select (nfds, readfds, writefds, excepfds, timeo);
}
