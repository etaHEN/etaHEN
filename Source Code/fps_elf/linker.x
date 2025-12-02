PHDRS {
	/*
	 * PF_X = 0x1
	 * PF_W = 0x2
	 * PF_R = 0x4
	 */
    phdr_text     PT_LOAD         FLAGS(0x5);
    phdr_data     PT_LOAD         FLAGS(0x6);
	phdr_rodata   PT_LOAD         FLAGS(0x4);
	phdr_relro    PT_LOAD         FLAGS(0x4);
	phdr_eh_frame PT_GNU_EH_FRAME FLAGS(0x4);
    phdr_dynamic  PT_DYNAMIC      FLAGS(0x0);
}

SECTIONS {

    PROVIDE (__payload_start = .);

    .text : {
		PROVIDE_HIDDEN(__text_start = .);
        *(.text .text.*);
		PROVIDE_HIDDEN(__text_stop = .);
    } : phdr_text

    .init : {
        *(.init)
    } : phdr_text

    .fini : {
        *(.fini)
    } : phdr_text

    .plt : {
        *(.plt)
    } : phdr_text

	. = ALIGN(0x4000); /* move to a new page in memory */

	.data : {
        *(.data);
		*(.data.*);
    } : phdr_data

    .bss (NOLOAD) : {
		PROVIDE_HIDDEN (__bss_start = .);
        *(.bss .bss.*);
        *(COMMON)
		PROVIDE_HIDDEN (__bss_end = .);
    } : phdr_data

	. = ALIGN(0x4000); /* move to a new page in memory */

    .rodata : {
        *(.rodata .rodata.*);
    } : phdr_rodata

	.gcc_except_table : {
		*(.gcc_except_table*)
	} : phdr_rodata

	.hash : {
		*(.hash);
    } : phdr_rodata

	. = ALIGN(0x4000); /* move to a new page in memory */

	.eh_frame_hdr : ALIGN(0x4000) {
		*(.eh_frame_hdr)
	} : phdr_eh_frame

	.eh_frame : ALIGN(0x10) {
		*(.eh_frame)
	} : phdr_eh_frame

	. = ALIGN(0x4000); /* move to a new page in memory */

    .data.rel.ro : {
        *(.data.rel.ro .data.rel.ro.*);
    } : phdr_relro

	.preinit_array : {
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP (*(.preinit_array*))
		PROVIDE_HIDDEN (__preinit_array_end = .);
	} : phdr_relro

    .init_array : {
        PROVIDE_HIDDEN(__init_array_start = .);
        KEEP (*(.init_array .init_array.*));
        PROVIDE_HIDDEN(__init_array_stop = .);
    } : phdr_relro

    .fini_array : {
        PROVIDE_HIDDEN(__fini_array_start = .);
        KEEP (*(.fini_array .fini_array.*));
        PROVIDE_HIDDEN(__fini_array_stop = .);
    } : phdr_relro

    .got : {
        *(.got);
    } : phdr_relro

    .got.plt : {
        *(.got.plt);
    } : phdr_relro

	.rela.dyn : {
        *(.rela.dyn) *(.rela);
    } : phdr_relro

    .rela.plt : {
        *(rela.plt);
    } : phdr_relro

    PROVIDE (__payload_end = .);

	/* this needs to be forced aligned to 0x4000 */
    .dynamic : ALIGN(0x4000) {
        PROVIDE_HIDDEN (_DYNAMIC = .);
        *(.dynamic);
    } : phdr_dynamic

    .dynsym : {
        *(.dynsym);
    } : phdr_dynamic

    .dynstr : {
        *(.dynstr);
    } : phdr_dynamic
}
