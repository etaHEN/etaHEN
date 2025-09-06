#pragma once

#include "../thread.hpp"

struct ElfLoaderBase {
	void run();
};

class ElfLoader : public ElfLoaderBase, public JThread<ElfLoaderBase> {
	friend struct ElfLoaderBase;

	public:
		void run();
};
