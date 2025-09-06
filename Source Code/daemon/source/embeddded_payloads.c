 __asm__(

	".global kstuff_start\n"
	".type   kstuff_start, @object\n"
	".align  16\n"
	"kstuff_start:\n"
    	".incbin \"assets/kstuff.elf\"\n"
	"kstuff_end:\n"
	    ".global kstuff_size\n"
	    ".type  kstuff_size, @object\n"
	    ".align  4\n"
	"kstuff_size:\n"
    	".int    kstuff_end - kstuff_start\n"


    ".global ps5debug_start\n"
	".type   ps5debug_start, @object\n"
	".align  16\n"
	"ps5debug_start:\n"
    	".incbin \"assets/ps5debug.elf\"\n"
	"ps5debug_end:\n"
	    ".global ps5debug_size\n"
	    ".type   ps5debug_size, @object\n"
	    ".align  4\n"
	"ps5debug_size:\n"
    	".int    ps5debug_end - ps5debug_start\n"


	".global shellui_elf_start\n"
	".type   shellui_elf_start, @object\n"
	".align  16\n"
	"shellui_elf_start:\n"
    	".incbin \"assets/shellui.elf\"\n"
	"shellui_elf_end:\n"
	    ".global shellui_elf_size\n"
	    ".type   shellui_elf_size, @object\n"
	    ".align  4\n"
	"shellui_prx_size:\n"
    	".int    shellui_elf_end - shellui_elf_start\n"

);