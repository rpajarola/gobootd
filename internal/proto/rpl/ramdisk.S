/*
 * RAM disk loader for RPL clients: boots a floppy image that RPL loaded
 * into conventional memory, as drive A:.
 *
 * bootd loads this program just below the image and sets the parameters
 * below. It lowers the memory size in the BIOS data area to keep DOS out
 * of both, takes over INT 13h for drive 0, copies the image's boot sector
 * to 0:7C00 and jumps to it. Writes go to the RAM disk and are lost on
 * reboot.
 *
 * 8086 code. Build with mkramdisk.sh, which writes ramdisk.bin.
 */
	.code16
	.arch	i8086
	.text
	.globl	_start
_start:
	jmp	main
	.org	4
magic:	.ascii	"RDSK"
imgseg:	.word	0	/* segment of the image */
nsect:	.word	0	/* sectors in the image */
spt:	.byte	0	/* sectors per track */
heads:	.byte	0
cyls:	.word	0
dtype:	.byte	0	/* BIOS drive type, for AH=08h */
	.byte	0
memkb:	.word	0	/* memory left to DOS, in KB: where this program starts */
needkb:	.word	0	/* memory the image needs, in KB: where it ends */
old13:	.long	0

main:
	cli
	/* The boot ROM may jump here with any CS:IP: make CS:0 our start. */
	call	1f
1:	pop	%bx
	sub	$1b, %bx
	mov	$4, %cl
	shr	%cl, %bx
	mov	%cs, %ax
	add	%bx, %ax
	push	%ax
	mov	$2f, %ax
	push	%ax
	lret
2:	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %ss
	mov	$stacktop, %sp
	sti
	cld

	int	$0x12
	cmp	needkb, %ax
	jae	3f
	mov	$nomem, %si
	jmp	fatal
3:	xor	%ax, %ax
	mov	%ax, %es
	mov	memkb, %ax
	mov	%ax, %es:0x413
	/* Say there is a floppy drive. */
	mov	%es:0x410, %ax
	test	$1, %al
	jnz	4f
	and	$0x3e, %al
	or	$1, %al
	mov	%ax, %es:0x410
4:	cli
	mov	%es:0x4c, %ax
	mov	%ax, old13
	mov	%es:0x4e, %ax
	mov	%ax, old13+2
	movw	$int13, %es:0x4c
	mov	%cs, %es:0x4e
	sti

	/* Copy the boot sector to 0:7C00 and start it from drive 0. */
	mov	imgseg, %ds
	xor	%si, %si
	mov	$0x7c00, %di
	mov	$256, %cx
	rep	movsw
	xor	%ax, %ax
	mov	%ax, %ds
	cli
	mov	%ax, %ss
	mov	$0x7c00, %sp
	sti
	xor	%dx, %dx
	ljmp	$0, $0x7c00

fatal:	lodsb
	or	%al, %al
	jz	5f
	mov	$0x0e, %ah
	mov	$7, %bx
	int	$0x10
	jmp	fatal
5:	hlt
	jmp	5b

nomem:	.asciz	"RPL RAM disk: not enough memory\r\n"

/* INT 13h: drive 0 is the RAM disk, other drives go to the BIOS. */
int13:
	cmp	$0, %dl
	je	1f
	ljmp	*%cs:old13
1:	sti
	cmp	$0x02, %ah
	je	rw
	cmp	$0x03, %ah
	je	rw
	cmp	$0x08, %ah
	je	params
	cmp	$0x15, %ah
	je	disktype
	cmp	$0x00, %ah	/* reset */
	je	ok
	cmp	$0x01, %ah	/* status */
	je	ok
	cmp	$0x04, %ah	/* verify */
	je	ok
	cmp	$0x05, %ah	/* format */
	je	ok
	cmp	$0x16, %ah	/* disk change: none */
	je	ok
	mov	$0x01, %ah	/* bad command */
fail:	stc
	lret	$2
ok:	xor	%ah, %ah
	clc
	lret	$2

disktype:
	mov	$0x01, %ah	/* floppy without change line */
	clc
	lret	$2

params:
	xor	%ax, %ax
	mov	%ax, %es
	mov	%es:0x410, %dx
	mov	$6, %cl
	shr	%cl, %dl
	and	$3, %dl
	inc	%dl		/* floppy drives */
	mov	%cs:heads, %dh
	dec	%dh
	mov	%cs:cyls, %ax
	dec	%ax
	mov	%al, %ch
	mov	$2, %cl
	shr	%cl, %ax
	and	$0xc0, %al
	or	%cs:spt, %al
	mov	%al, %cl
	mov	%cs:dtype, %bl
	xor	%bh, %bh
	les	%es:0x78, %di	/* the diskette parameter table */
	xor	%ax, %ax
	clc
	lret	$2

/* Read (AH=02h) or write (AH=03h) AL sectors at CH/CL/DH to or from ES:BX. */
rw:
	push	%bx
	push	%cx
	push	%dx
	push	%si
	push	%di
	push	%bp
	push	%ds
	push	%es
	mov	%ax, %bp	/* function and count */
	/* sector, 1-based */
	mov	%cl, %al
	and	$0x3f, %al
	jz	badsec
	cmp	%cs:spt, %al
	ja	badsec
	cmp	%cs:heads, %dh
	jae	badsec
	push	%ax		/* AL: sector */
	mov	%cl, %ah
	mov	$6, %cl
	shr	%cl, %ah
	mov	%ch, %al	/* AX: cylinder */
	mov	%dh, %cl
	xor	%ch, %ch	/* CX: head */
	xor	%dx, %dx
	mov	%cs:heads, %dl
	mul	%dx		/* AX = cylinder * heads */
	add	%cx, %ax
	xor	%dx, %dx
	mov	%cs:spt, %dl
	mul	%dx		/* AX = (cylinder * heads + head) * spt */
	pop	%cx
	xor	%ch, %ch
	dec	%cx
	add	%cx, %ax	/* AX = LBA */
	jc	badsec
	mov	%bp, %cx
	xor	%ch, %ch	/* CX = count */
	jcxz	badsec
	mov	%ax, %dx
	add	%cx, %dx
	jc	badsec
	cmp	%cs:nsect, %dx
	ja	badsec
	/* image segment of the LBA */
	mov	$5, %cl
	shl	%cl, %ax
	add	%cs:imgseg, %ax
	mov	%ax, %si	/* SI: image segment */
	/* normalize ES:BX to DX:DI */
	mov	%bx, %di
	mov	$4, %cl
	shr	%cl, %bx
	mov	%es, %dx
	add	%bx, %dx
	and	$0x0f, %di
	mov	%bp, %cx
	xor	%ch, %ch
	mov	%di, %bx	/* BX: offset in the buffer segment */
6:	push	%cx
	mov	$256, %cx
	mov	%bp, %ax
	cmp	$0x02, %ah
	jne	7f
	mov	%si, %ds	/* read: image -> buffer */
	mov	%dx, %es
	mov	%bx, %di
	push	%si
	xor	%si, %si
	rep	movsw
	pop	%si
	jmp	8f
7:	mov	%dx, %ds	/* write: buffer -> image */
	mov	%si, %es
	push	%si
	mov	%bx, %si
	xor	%di, %di
	rep	movsw
	pop	%si
8:	add	$32, %si
	add	$32, %dx
	pop	%cx
	loop	6b
	mov	%bp, %ax
	xor	%ah, %ah
	pop	%es
	pop	%ds
	pop	%bp
	pop	%di
	pop	%si
	pop	%dx
	pop	%cx
	pop	%bx
	clc
	lret	$2
badsec:
	pop	%es
	pop	%ds
	pop	%bp
	pop	%di
	pop	%si
	pop	%dx
	pop	%cx
	pop	%bx
	mov	$0x0400, %ax	/* sector not found */
	stc
	lret	$2

	.balign	2
stack:	.fill	256, 1, 0
stacktop:
