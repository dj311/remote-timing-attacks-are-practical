/* ISC License

   Copyright (c) 2019, Daniel Jones

   Based upon https://github.com/Roguelazer/rdtsc/blob/master/src/rdtsc.c
   with the following licensing.

   Copyright (c) 2015-2016, James Brown

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
   SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
   OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
   CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

*/


/*

  Timed Messenger
  ===============
  Little C library for sending and receiving TCP messages over a given
  socket with /accurate/ timing information. The library uses the rdtsc
  and cpuid instructions to count cycles, and disable out-of-order
  execution temporarily.

  References:
  - https://www.geeksforgeeks.org/how-to-call-a-c-function-in-python/
  - https://github.com/Roguelazer/rdtsc/
  - https://stackoverflow.com/questions/9200560/

*/


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>


unsigned long long get_cycles() {
  long long out;
  asm volatile(
               "CPUID;"
               "RDTSCP;"
               "SHLQ $32,%%rdx;"
               "ORQ %%rdx,%%rax;"
               "MOVQ %%rax,%0;"
               :"=r"(out)
               : /*no input*/
               :"rdx","rax", "rcx"
               );
  return out;
}


typedef struct {
  unsigned long long start_time;
  unsigned long long end_time;
  int response_length;
  char response[4096];
} s_timed_response;


s_timed_response timed_send_and_receive(int conn_fd,
                                        char* message,
                                        unsigned int message_length) {
  s_timed_response return_buf;
  return_buf.start_time = 0;
  return_buf.end_time = 0;
  memset(return_buf.response, 0, 4096);
  return_buf.response_length = 0;

  return_buf.start_time = get_cycles();

  send(conn_fd, message, message_length, 0);
  return_buf.response_length = recv(conn_fd, return_buf.response, 4096, 0);

  return_buf.end_time = get_cycles();

  return return_buf;
}

