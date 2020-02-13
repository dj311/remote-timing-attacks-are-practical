/*

  Timed Messenger
  ===============
  Little C library for sending and receiving TCP messages over a given
  socket with /accurate/ timing information. The library uses the rdtsc
  and cpuid instructions to count cycles, and disable out-of-order
  execution temporarily.

  Final timing code is based on the Appendix in "How to Benchmark Code
  Execution Times on Intel IA-32 and IA-64 Instruction Set Architectures"
  by Gabriele Paoloni, Intel (https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf).

  Other references:
  - https://www.geeksforgeeks.org/how-to-call-a-c-function-in-python/
  - https://github.com/Roguelazer/rdtsc/
  - https://stackoverflow.com/questions/9200560/

*/


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>


// Structure of the response from the timed_send_and_receive
// function. This is the C equivelant to TimedResponse in
// timed_messenger.py.
typedef struct
{
  unsigned long long start_time;
  unsigned long long end_time;
  int response_length;
  char response[4096];
} s_timed_response;


s_timed_response
timed_send_and_receive(
  int conn_fd,
  char *message,
  unsigned int message_length
)
{
  s_timed_response return_buf;
  return_buf.start_time = 0;
  return_buf.end_time = 0;
  memset(return_buf.response, 0, 4096);
  return_buf.response_length = 0;

  unsigned start_cycles_high, start_cycles_low;
  unsigned end_cycles_high, end_cycles_low;

  /* *INDENT-OFF* */
  asm volatile (
    "CPUID;"
    "RDTSC;"
    "mov %%edx, %0;"
    "mov %%eax, %1;"
    : "=r" (start_cycles_high), "=r" (start_cycles_low)
    :
    : "%rax", "%rbx", "%rcx", "%rdx"
  );
  /* *INDENT-ON* */

  send(conn_fd, message, message_length, 0);
  return_buf.response_length = recv(conn_fd, return_buf.response, 4096, 0);

  /* *INDENT-OFF* */
  asm volatile(
    "RDTSCP;"
    "mov %%edx, %0;"
    "mov %%eax, %1;"
    "CPUID;"
    : "=r" (end_cycles_high), "=r" (end_cycles_low)
    :
    : "%rax", "%rbx", "%rcx", "%rdx"
  );
  /* *INDENT-ON* */

  return_buf.start_time =
    ((unsigned long long)start_cycles_high << 32) | start_cycles_low;
  return_buf.end_time =
    ((unsigned long long)end_cycles_high << 32) | end_cycles_low;

  return return_buf;
}
