
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <memory>
#include "LzmaEnc.h"
#include "LzmaDec.h"

static void *_lzmaAlloc(ISzAllocPtr, size_t size) {
	return new uint8_t[size];
}
static void _lzmaFree(ISzAllocPtr, void *addr) {
	if (!addr)
		return;

	delete[] reinterpret_cast<uint8_t *>(addr);
}

static ISzAlloc _allocFuncs = {
	_lzmaAlloc, _lzmaFree
};



std::unique_ptr<uint8_t[]> lzmaCompress(const uint8_t *input, uint32_t inputSize, uint32_t *outputSize) {
	std::unique_ptr<uint8_t[]> result;

	// set up properties
	CLzmaEncProps props;
	LzmaEncProps_Init(&props);
	if (inputSize >= (1 << 20))
		props.dictSize = 1 << 20; // 1mb dictionary
	else
		props.dictSize = inputSize; // smaller dictionary = faster!
	props.fb = 40;

	// prepare space for the encoded properties
	SizeT propsSize = 5;
	uint8_t propsEncoded[5];

	// allocate some space for the compression output
	// this is way more than necessary in most cases...
	// but better safe than sorry
	//   (a smarter implementation would use a growing buffer,
	//    but this requires a bunch of fuckery that is out of
	///   scope for this simple example)
	SizeT outputSize64 = inputSize * 1.5;
	if (outputSize64 < 1024)
		outputSize64 = 1024;
	auto output = std::make_unique<uint8_t[]>(outputSize64);

	int lzmaStatus = LzmaEncode(
		output.get(), &outputSize64, input, inputSize,
		&props, propsEncoded, &propsSize, 0,
		NULL,
		&_allocFuncs, &_allocFuncs);

	*outputSize = outputSize64 + 13;
	if (lzmaStatus == SZ_OK) {
		// tricky: we have to generate the LZMA header
		// 5 bytes properties + 8 byte uncompressed size
		result = std::make_unique<uint8_t[]>(outputSize64 + 13);
		uint8_t *resultData = result.get();

		memcpy(resultData, propsEncoded, 5);
		for (int i = 0; i < 8; i++)
			resultData[5 + i] = (inputSize >> (i * 8)) & 0xFF;
		memcpy(resultData + 13, output.get(), outputSize64);
	}

	return result;
}


std::unique_ptr<uint8_t[]> lzmaDecompress(const uint8_t *input, uint32_t inputSize, uint32_t *outputSize) {
	if (inputSize < 13)
		return NULL; // invalid header!

	// extract the size from the header
	UInt64 size = 0;
	for (int i = 0; i < 8; i++)
		size |= (input[5 + i] << (i * 8));

	if (size <= (256 * 1024 * 1024)) {
		auto blob = std::make_unique<uint8_t[]>(size);

		ELzmaStatus lzmaStatus;
		SizeT procOutSize = size, procInSize = inputSize - 13;
		int status = LzmaDecode(blob.get(), &procOutSize, &input[13], &procInSize, input, 5, LZMA_FINISH_END, &lzmaStatus, &_allocFuncs);

		if (status == SZ_OK && procOutSize == size) {
			*outputSize = size;
			return blob;
		}
	}

	return NULL;
}



void hexdump(const uint8_t *buf, int size) {
	int lines = (size + 15) / 16;
	for (int i = 0; i < lines; i++) {
		printf("%08x | ", i * 16);

		int lineMin = i * 16;
		int lineMax = lineMin + 16;
		int lineCappedMax = (lineMax > size) ? size : lineMax;

		for (int j = lineMin; j < lineCappedMax; j++)
			printf("%02x ", buf[j]);
		for (int j = lineCappedMax; j < lineMax; j++)
			printf("   ");

		printf("| ");

		for (int j = lineMin; j < lineCappedMax; j++) {
			if (buf[j] >= 32 && buf[j] <= 127)
				printf("%c", buf[j]);
			else
				printf(".");
		}
		printf("\n");
	}
}


void testIt(const uint8_t *input, int size) {
	printf("Test Input:\n");
	hexdump(input, size);

	uint32_t compressedSize;
	auto compressedBlob = lzmaCompress(input, size, &compressedSize);

	if (compressedBlob) {
		printf("Compressed:\n");
		hexdump(compressedBlob.get(), compressedSize);
	} else {
		printf("Nope, we screwed it\n");
		return;
	}

	// let's try decompressing it now
	uint32_t decompressedSize;
	auto decompressedBlob = lzmaDecompress(compressedBlob.get(), compressedSize, &decompressedSize);

	if (decompressedBlob) {
		printf("Decompressed:\n");
		hexdump(decompressedBlob.get(), decompressedSize);
	} else {
		printf("Nope, we screwed it (part 2)\n");
		return;
	}

	printf("----------\n");
}

void testIt(const char *string) {
	testIt((const uint8_t *)string, strlen(string));
}


int main(int argc, char **argv) {
	testIt("a");
	testIt("here is a cool string");
	testIt("here's something that should compress pretty well: abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef");

	return 0;
}