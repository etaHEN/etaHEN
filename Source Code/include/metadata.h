/* SIE CONFIDENTIAL
PlayStation(R)4 Programmer Tool Runtime Library Release 04.508.001
* Copyright (C) 2016 Sony Interactive Entertainment Inc.
* All Rights Reserved.
*/

#if !defined(_SCE_GPU_ADDRESS_METADATA_H)
#define _SCE_GPU_ADDRESS_METADATA_H

unsigned getPipeIndexOfTile(unsigned x, unsigned y, unsigned num_pipes)
{
	unsigned pipe = 0;
	pipe |= ( ((x>>0) ^ (y>>0) ^ (x>>1))	& 0x1 ) << 0;
	pipe |=	( ((x>>1) ^ (y>>1))				& 0x1 ) << 1;
	pipe |=	( ((x>>2) ^ (y>>2))				& 0x1 ) << 2;
	if(num_pipes == 16)
		pipe |=	( ((x>>3) ^ (y>>2))				& 0x1 ) << 3;
	return pipe;
}

unsigned CmaskOffsetInNybbles(unsigned tileX, unsigned tilesWide, unsigned tileY, bool isLinear, bool isNeoMode)
{
	const unsigned pipe_interleave = 256;
	const unsigned cl_size = 256; // 256 BYTES per PIPE in a CACHELINE
	const unsigned num_pipes = isNeoMode ? 16 : 8;
	const unsigned macro_shift = (16 - num_pipes) >> 3;
	const unsigned cl_width = 64;
	const unsigned cl_height = num_pipes << 2;
	const unsigned cl_x = tileX / cl_width;
	const unsigned cl_y = tileY / cl_height;
	const unsigned surf_pitch_cl = (tilesWide + cl_width - 1) / cl_width;
	const unsigned cl_offset = isLinear ? 0 : ((cl_x + surf_pitch_cl * cl_y) * cl_size);

	const unsigned macro_x = (isLinear ? tileX : (tileX % cl_width)) / 4;
	const unsigned macro_y = (isLinear ? tileY : (tileY % cl_height)) / 4;
	const unsigned macro_pitch = (isLinear ? tilesWide : cl_width) / 4;
	unsigned macro_offset = (macro_x + macro_y * macro_pitch) << macro_shift;

	macro_offset &= ~3;
	macro_offset |= (( (tileX>>1) ^ (tileY>>0) )&1) << 0;
	macro_offset |= (( (tileX>>1)              )&1) << 1;

	const unsigned tile_number = cl_offset + macro_offset;
	const unsigned device_address = tile_number >> 1;
	const unsigned pipe = getPipeIndexOfTile(tileX, tileY, num_pipes);
	const unsigned final_address = (device_address % pipe_interleave) + (pipe * pipe_interleave) + (device_address / pipe_interleave) * pipe_interleave * num_pipes;

	return (final_address << 1) | (tile_number & 1);
}

unsigned HtileOffsetInDwords(unsigned tileX, unsigned tilesWide, unsigned tileY, bool isLinear, bool isNeoMode)
{
	const unsigned pipe_interleave = 256;
	const unsigned cl_size = 512; // 512 DWORDS per PIPE in a CACHELINE
	const unsigned num_pipes = isNeoMode ? 16 : 8;
	const unsigned macro_shift = (16 - num_pipes) >> 3;
	const unsigned cl_width = num_pipes << 3;
	const unsigned cl_height = 64;
	const unsigned cl_x = tileX / cl_width;
	const unsigned cl_y = tileY / cl_height;
	const unsigned surf_pitch_cl = (tilesWide + cl_width - 1) / cl_width;
	const unsigned cl_offset = isLinear ? 0 : ((cl_x + surf_pitch_cl * cl_y) * cl_size);

	const unsigned macro_x = (isLinear ? tileX : (tileX % cl_width)) / 4;
	const unsigned macro_y = (isLinear ? tileY : (tileY % cl_height)) / 4;
	const unsigned macro_pitch = (isLinear ? tilesWide : cl_width) / 4;
	unsigned macro_offset = (macro_y * macro_pitch + macro_x) << macro_shift;

	macro_offset &= ~3;
	macro_offset |= (( (tileX>>1) ^ (tileY>>0) )&1) << 0;
	macro_offset |= (( (tileX>>1)              )&1) << 1;

	const unsigned tile_number = cl_offset + macro_offset;
	const unsigned device_address = tile_number << 2;
	const unsigned pipe = getPipeIndexOfTile(tileX, tileY, num_pipes);
	const unsigned final_address = (device_address % pipe_interleave) + (pipe * pipe_interleave) + (device_address / pipe_interleave) * pipe_interleave * num_pipes;

	return final_address / 4;
}

#endif