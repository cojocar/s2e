.text
.global _start

_start:
  /* Enable forking */
//  .WORD 0xFF090000
  
  /* Sleep for 10 seconds */
  mov r0, #10
  .WORD 0xFF320000

  /* Kill this state */
  mov r0, #0
  adr r1, str_kill
  .WORD 0xFF060000

.align 2
str_kill:
    .ascii "Normal exit after 10s sleep\0"

