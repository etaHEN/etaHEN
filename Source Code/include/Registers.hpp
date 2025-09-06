#pragma once

namespace libdebug
{
	struct regs
    {
        uint64_t r_r15;
        uint64_t r_r14;
        uint64_t r_r13;
        uint64_t r_r12;
        uint64_t r_r11;
        uint64_t r_r10;
        uint64_t r_r9;
        uint64_t r_r8;
        uint64_t r_rdi;
        uint64_t r_rsi;
        uint64_t r_rbp;
        uint64_t r_rbx;
        uint64_t r_rdx;
        uint64_t r_rcx;
        uint64_t r_rax;
        uint32_t r_trapno;
        uint16_t r_fs;
        uint16_t r_gs;
        uint32_t r_err;
        uint16_t r_es;
        uint16_t r_ds;
        uint64_t r_rip;
        uint64_t r_cs;
        uint64_t r_rflags;
        uint64_t r_rsp;
        uint64_t r_ss;
	};


    struct envxmm
    {
        uint16_t en_cw; /* control word (16bits) */
        uint16_t en_sw; /* status word (16bits) */
        uint8_t en_tw; /* tag word (8bits) */
        uint8_t en_zero;
        uint16_t en_opcode; /* opcode last executed (11 bits ) */
        uint64_t en_rip; /* floating point instruction pointer */
        uint64_t en_rdp; /* floating operand pointer */
        uint32_t en_mxcsr; /* SSE sontorol/status register */
        uint32_t en_mxcsr_mask; /* valid bits in mxcsr */
	};

    struct acc
    {
        uint8_t fp_bytes[10];
	private:
        uint8_t fp_pad[6];
	};

    struct xmmacc
    {
        uint8_t xmm_bytes[16];
	};

    struct ymmacc
    {
        uint8_t ymm_bytes[16];
	};

    struct xstate_hdr
    {
        uint64_t xstate_bv;
	private:
        uint8_t xstate_rsrv0[16];
        uint8_t xstate_rsrv[40];
	};

    struct savefpu_xstate
    {
        xstate_hdr sx_hd;
        ymmacc sx_ymm[16];
	};

    struct fpregs
    {
        envxmm svn_env;
        acc sv_fp[8];
        xmmacc sv_xmm[16];
	private:
        uint8_t sv_pad[96];
	public:
        savefpu_xstate sv_xstate;
	};

    struct dbregs
    {
        uint64_t dr0;
        uint64_t dr1;
        uint64_t dr2;
        uint64_t dr3;
        uint64_t dr4;
        uint64_t dr5;
        uint64_t dr6;
        uint64_t dr7;
        uint64_t dr8;
        uint64_t dr9;
        uint64_t dr10;
        uint64_t dr11;
        uint64_t dr12;
        uint64_t dr13;
        uint64_t dr14;
        uint64_t dr15;
	};
}