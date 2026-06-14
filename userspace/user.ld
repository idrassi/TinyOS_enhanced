/*=============================================================================
 * user.ld - Linker Script for User-Mode ELF Programs
 *=============================================================================*/

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);  /* PF_R | PF_X */
    rodata PT_LOAD FLAGS(4);  /* PF_R */
    data   PT_LOAD FLAGS(6);  /* PF_R | PF_W */
}

SECTIONS
{
    /* Load user programs at virtual address 0x08000000 (128MB mark) */
    . = 0x08000000;

    /* Code section */
    . = ALIGN(4K);
    .text : {
        __user_text_start = .;
        *(.text)
        *(.text.*)
        __user_text_end = .;
    } :text

    /* Read-only data */
    . = ALIGN(4K);
    .rodata : {
        __user_rodata_start = .;
        *(.rodata)
        *(.rodata.*)
        __user_rodata_end = .;
    } :rodata

    /* Initialized data */
    . = ALIGN(4K);
    .data : {
        /* Keep the RW PT_LOAD anchored in user space even for programs that
         * have no initialized data. */
        BYTE(0)
        . = ALIGN(4);
        __user_data_start = .;
        *(.data)
        *(.data.*)
        __user_data_end = .;
    } :data

    /* Uninitialized data (BSS) */
    . = ALIGN(4K);
    .bss : {
        __user_bss_start = .;
        *(COMMON)
        *(.bss)
        *(.bss.*)
        __user_bss_end = .;
    } :data

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}
