.text
.global _start

_start:
  /* Enable forking */
  .WORD 0xFF090000

  /* Make value symbolic */
  adr r0, symbolic_buffer
  mov r1, #4
  adr r2, str_buffer_name
  .WORD 0xFF030000

  ldr r0, symbolic_buffer
  cmp r0, #0
  beq eq_zero

  /* Kill this state */
  mov r0, #0
  adr r1, str_kill_neq_zero 
  .WORD 0xFF060000

loop0:
  b loop0

eq_zero:
  /* And also kill this state */
  mov r0, #1
  adr r1, str_kill_eq_zero
  .WORD 0xFF060000

loop1:
  b loop1



.align 2
symbolic_buffer:
  .long 0

.align 2
str_buffer_name:
    .ascii "symbolic value\0"
.align 2
str_kill_neq_zero:
    .ascii "Not equal zero\0"
.align 2
str_kill_eq_zero:
    .ascii "Equal zero\0"

