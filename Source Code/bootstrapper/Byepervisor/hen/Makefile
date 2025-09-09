PS5_HOST ?= ps5
PS5_PORT ?= 9021

ELF := hen.elf
BIN := hen.bin

CFLAGS := -std=c++11 -Wall -Werror -D_KERNEL -I./include -O2 -fno-builtin -nostartfiles -nostdlib -fno-stack-protector -fno-plt -fPIC -Wno-error=frame-address
#SFLAGS := -nostartfiles -nostdlib -fPIC
LFLAGS := -Xlinker -T ./link.x -Wl,--build-id=none

ODIR        := build
SDIR        := src
CXXFILES    := $(wildcard $(SDIR)/*.cpp)
SFILES      := $(wildcard $(SDIR)/*.s)
OBJS        := $(patsubst $(SDIR)/%.cpp, $(ODIR)/%.o, $(CXXFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

$(ELF): $(ODIR) $(OBJS)
	$(CXX) $(ODIR)/*.o -o $(ELF) $(CFLAGS) $(LFLAGS)
	objcopy -O binary $(ELF) $(BIN)

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(CXX) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(AS) -c -o $@ $< $(SFLAGS)

$(ODIR):
	@mkdir $@

clean:
	rm -f $(ELF) $(BIN) $(ODIR)/*.o

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^

debug: $(ELF)
	gdb \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"
