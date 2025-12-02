#!/bin/bash

# Assuming the script is intended to run in a Unix-like environment

# Remove directories recursively and ignore nonexistent files
clear
rm -rf bin
rm -rf unpacker/CMakeFiles
rm -rf daemon/CMakeFiles
rm -rf shellui/CMakeFiles
rm -rf libNineS/CMakeFiles
rm     daemon/assets/shellui.elf
rm -rf util/CMakeFiles
rm -rf bootstrapper/CMakeFiles

# Run cmake if the directory is set correctly
"${PS5_PAYLOAD_SDK}/bin/prospero-cmake"
if ! "${PS5_PAYLOAD_SDK}/bin/prospero-cmake" -S . -B .; then
    echo "Failed to run cmake. Check if PS5_PAYLOAD_SDK is set correctly and cmake is installed."
    exit 1
fi

# Execute the make command
make clean -C bootstrapper/Byepervisor/hen
make -C bootstrapper/Byepervisor/hen
make -j30
