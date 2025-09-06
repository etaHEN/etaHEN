#pragma once

#include "kernel.hpp"
#include "kernel/kernel.hpp"

namespace {

static constexpr size_t TRAPFRAME_SIZE = 0x110;

}

class TrapFrame : public KernelObject<TrapFrame, TRAPFRAME_SIZE> {

	static constexpr size_t RAX_OFFSET = 0x30;
	static constexpr size_t RBX_OFFSET = 0x38;
	static constexpr size_t RCX_OFFSET = 0x18;
	static constexpr size_t RDX_OFFSET = 0x10;
	static constexpr size_t RSI_OFFSET = 0x08;
	static constexpr size_t RDI_OFFSET = 0x00;
	static constexpr size_t R8_OFFSET  = 0x20;
	static constexpr size_t R9_OFFSET  = 0x28;
	static constexpr size_t R10_OFFSET = 0x48;
	static constexpr size_t R11_OFFSET = 0x50;
	static constexpr size_t R12_OFFSET = 0x58;
	static constexpr size_t R13_OFFSET = 0x60;
	static constexpr size_t R14_OFFSET = 0x68;
	static constexpr size_t R15_OFFSET = 0x70;
	static constexpr size_t RBP_OFFSET = 0x40;
	static constexpr size_t RSP_OFFSET = 0x100;
	static constexpr size_t RIP_OFFSET = 0xe8;



	public:
		TrapFrame(uintptr_t addr) : KernelObject(addr) {}

		TrapFrame &setFrame(const TrapFrame *frame) {
			memcpy(buf, frame->buf, sizeof(buf));
			return *this;
		}

		uint64_t getRax() {
			return get<uint64_t, RAX_OFFSET>();
		}

		TrapFrame &setRax(uint64_t rax) {
			set<RAX_OFFSET>(rax);
			return *this;
		}

		uint64_t getRbx() {
			return get<uint64_t, RBX_OFFSET>();
		}

		TrapFrame &setRbx(uint64_t rbx) {
			set<RBX_OFFSET>(rbx);
			return *this;
		}

		uint64_t getRcx() {
			return get<uint64_t, RCX_OFFSET>();
		}


		TrapFrame &setRcx(uint64_t rcx) {
			set<RCX_OFFSET>(rcx);
			return *this;
		}

		uint64_t getRdx() {
			return get<uint64_t, RDX_OFFSET>();
		}

		TrapFrame &setRdx(uint64_t rdx) {
			set<RDX_OFFSET>(rdx);
			return *this;
		}

		uint64_t getRsi() {
			return get<uint64_t, RSI_OFFSET>();
		}

		TrapFrame &setRsi(uint64_t rsi) {
			set<RSI_OFFSET>(rsi);
			return *this;
		}

		uint64_t getRdi() {
			return get<uint64_t, RDI_OFFSET>();
		}

		TrapFrame &setRdi(uint64_t rdi) {
			set<RDI_OFFSET>(rdi);
			return *this;
		}

		uint64_t getR8() {
			return get<uint64_t, R8_OFFSET>();
		}

		TrapFrame &setR8(uint64_t r8) {
			set<R8_OFFSET>(r8);
			return *this;
		}

		uint64_t getR9() {
			return get<uint64_t, R9_OFFSET>();
		}

		TrapFrame &setR9(uint64_t r9) {
			set<R9_OFFSET>(r9);
			return *this;
		}

		uint64_t getR10() {
			return get<uint64_t, R10_OFFSET>();
		}

		TrapFrame &setR10(uint64_t r10) {
			set<R10_OFFSET>(r10);
			return *this;
		}

		uint64_t getR11() {
			return get<uint64_t, R11_OFFSET>();
		}

		TrapFrame &setR11(uint64_t r11) {
			set<R11_OFFSET>(r11);
			return *this;
		}

		uint64_t getR12() {
			return get<uint64_t, R12_OFFSET>();
		}
		TrapFrame &setR12(uint64_t r12) {
			set<R12_OFFSET>(r12);
			return *this;
		}

		uint64_t getR13() {
			return get<uint64_t, R13_OFFSET>();
		}

		TrapFrame &setR13(uint64_t r13) {
			set<R13_OFFSET>(r13);
			return *this;
		}

		uint64_t getR14() {
			return get<uint64_t, R14_OFFSET>();
		}

		TrapFrame &setR14(uint64_t r14) {
			set<R14_OFFSET>(r14);
			return *this;
		}

		uint64_t getR15() {
			return get<uint64_t, R15_OFFSET>();
		}

		TrapFrame &setR15(uint64_t r15) {
			set<R15_OFFSET>(r15);
			return *this;
		}

		uint64_t getRbp() {
			return get<uint64_t, RBP_OFFSET>();
		}

		TrapFrame &setRbp(uint64_t rbp) {
			set<RBP_OFFSET>(rbp);
			return *this;
		}

		uint64_t getRsp() {
			return get<uint64_t, RSP_OFFSET>();
		}

		TrapFrame &setRsp(uint64_t rsp) {
			set<RSP_OFFSET>(rsp);
			return *this;
		}

		uint64_t getRip() {
			return get<uint64_t, RIP_OFFSET>();
		}

		TrapFrame &setRip(uint64_t rip) {
			set<RIP_OFFSET>(rip);
			return *this;
		}
};
