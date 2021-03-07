.code16
.org 0x7c00
start: 
        movw %cs,%ax
        movw %ax,%ds
        movw %ax,%ss
        movw $start, %sp

        movb $0x00,%ah
        movb $0x03,%al
        int $0x10

wait_input:
        mov $0x00, %ah
        int $0x16
        cmpb $0x31, %al
        mov $0x31, 0x7e00
        je load_drive
        cmpb $0x32, %al
        mov $0x32, 0x7e00
        je load_drive
        cmpb $0x33, %al
        mov $0x33, 0x7e00
        je load_drive
        cmpb $0x34, %al
        mov $0x34, 0x7e00
        je load_drive
        cmpb $0x35, %al
        mov $0x35, 0x7e00
        je load_drive
        cmpb $0x36, %al
        mov $0x36, 0x7e00
        je load_drive
        jmp wait_input

load_drive: 
    movw $0x1000,%bx
    movw %bx,%es
    xorw %bx,%bx
    movb $0x30,%al
    movb $0x01,%dl
    movb $0x00,%dh
    movb $0x00,%ch
    movb $0x01,%cl
    movb $0x02,%ah
    int $0x13

enable_protected_mode: 
        cli
        lgdt gdt_info   
        inb $0x92,%al
        orb $2,%al
        outb %al, $0x92
        movl %cr0, %eax
        orb $1,%al
        movl %eax, %cr0
        ljmp $0x8, $protected_mode

gdt: 
        .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        .byte 0xff,0xff,0x00,0x00,0x00,0x9A,0xCF,0x00
        .byte 0xff,0xff,0x00,0x00,0x00,0x92,0xCF,0x00

gdt_info: 
    .word gdt_info - gdt 
    .word gdt, 0

.code32
protected_mode: 
        movw $0x10,%ax
        movw %ax,%es
        movw %ax,%ds
        movw %ax,%ss
        call 0x10000

.zero (512 - (. - start) - 2)
.byte 0x55, 0xAA