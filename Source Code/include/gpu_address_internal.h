/* SIE CONFIDENTIAL
PlayStation(R)5 Programmer Tool Runtime Library Release 2.00.00.09-00.00.00.0.1
* Copyright (C) 2019 Sony Interactive Entertainment Inc.
*/

#pragma once

#include <stddef.h>

#if !defined(DOXYGEN_IGNORE)
#if defined(__PROSPERO__) || defined(SCE_AGC_GPU_ADDRESS_STATIC_EXPORT)
#define SCE_AGC_GPU_ADDRESS_EXPORT
#else // #if defined(__PROSPERO__) || defined(SCE_AGC_GPU_ADDRESS_STATIC_EXPORT)
#if defined(SCE_AGC_GPU_ADDRESS_DLL_EXPORT)
#define SCE_AGC_GPU_ADDRESS_EXPORT 
#else // #if defined(SCE_AGC_GPU_ADDRESS_DLL_EXPORT)
#define SCE_AGC_GPU_ADDRESS_EXPORT 
#endif // #else // #if defined(SCE_AGC_GPU_ADDRESS_DLL_EXPORT)
#endif // #else // #if defined(__PROSPERO__) || defined(SCE_AGC_GPU_ADDRESS_STATIC_EXPORT)
#endif
#if defined(__clang__)
#define SCE_AGC_ADDRESS_DEPRECATED_MSG(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER) || (__cplusplus >= 201402L)
#define SCE_AGC_ADDRESS_DEPRECATED_MSG(msg) [[deprecated(msg)]]
#else
#define SCE_AGC_ADDRESS_DEPRECATED_MSG(msg)
#endif
#define Status int

namespace sce {

/** @brief The namespace for the AgcGpuAddress library.
 */
namespace AgcGpuAddress {

/** @brief The greatest number of mip levels that a surface can have.
 */
static constexpr unsigned kMaxMipLevels = 15;

/** @brief Defines the error codes that AgcGpuAddress library functions return.
 */

/** @brief List of surface dimensions.
 *
 * Dimensionality of the surface (1D, 2D, 3D).
 */
enum class SurfaceDimension : uint32_t
{
	k1d = 0, ///< 1D surface.
	k2d = 1, ///< 2D surface.
	k3d = 2, ///< 3D surface.
};

/** @brief List of supported tile modes.
 *
 * Directs hardware to shuffle and mix address bits to increase memory performance.
 */
enum class TileMode : uint32_t
{
	kLinear = 0,        ///< Linear pixel storage. 256-byte blocks. Generally not recommended except for 1D surfaces. Be careful with padding in the X direction.
	kStandard256B = 1,  ///< Recommended for common use. 256-byte blocks. Worst performance, but smallest alignment.
	kStandard4KB = 5,   ///< Recommended for common use. 4 KB blocks. Medium performance, and medium alignment.
	kStandard64KB = 9,  ///< Recommended for common use. 64 KB blocks. Best performance, but largest alignment.
	kPrt = 17,          ///< Recommended for partially-resident textures (PRTs). 64 KB blocks.
	kDepth = 24,        ///< Required for depth targets. 64 KB blocks.
	kRenderTarget = 27, ///< Recommended for render targets. This is also the only tile mode supported for video out, and color MSAA.
};

/** @brief Specifies the number of contiguous buffer elements to swizzle as a single block, if buffer swizzling is enabled.
 */
enum class BufferSwizzleStride : uint32_t
{
	k8  = 0x0, ///< 8 records swizzled together.
	k16 = 0x1, ///< 16 records swizzled together.
	k32 = 0x2, ///< 32 records swizzled together.
	k64 = 0x3, ///< 64 records swizzled together.
};

/** @brief Describes the mapping of each bit of a nybble to the clear regions within a tile.
 */
enum class CmaskBitLayout : uint32_t
{
	kVertical23 = 0,   ///< Bit 2 is the top half. Bit 3 is the bottom half. MSAA is enabled.
	kHorizontal23 = 1, ///< Bit 2 is the left half. Bit 3 is the bottom half. MSAA is enabled.
	kVertical0123 = 2, ///< Bit 0 is the top quadrant. Bit 1 is the middle-top quadrant. Bit 2 is the middle-bottom quadrant. Bit 3 is the bottom quadrant.
	kSquare0123 = 3,   ///< Bit 0 is the top-left quadrant. Bit 1 is the top-right quadrant. Bit 2 is the bottom-left quadrant. Bit 3 is the bottom-right quadrant.
	kSquare0213 = 4,   ///< Bit 0 is the top-left quadrant. Bit 1 is the bottom-left quadrant. Bit 2 is the top-right quadrant. Bit 3 is the bottom-right quadrant.
};

/**
 * @brief Describes a surface. Usually filled out by an Agc helper to generate a SurfaceSummary.
 *
 * @sa computeSurfaceSummary()
 */
struct SurfaceDescription
{
	TileMode m_tileMode;               ///< The tile mode that hardware uses to shuffle and mix address bits in order to increase memory performance.
	SurfaceDimension m_dimension;      ///< The dimensionality of the surface (1D, 2D, 3D).
	uint32_t m_bytesPerElementLog2;    ///< The <c>log2</c> bytes per texel for uncompressed surfaces, <c>log2</c> bytes per block for compressed surfaces.
	uint32_t m_multiElementMultiplier; ///< Always <c>1</c> unless <c>32_32_32</c> format, which is indicated by the value <c>3</c>.
	uint32_t m_texelsPerElementWide;   ///< <c>1</c> for uncompressed surfaces. <c>4</c> for compressed surfaces. <c>2</c> for <c>4:2:2</c> surfaces.
	uint32_t m_texelsPerElementTall;   ///< <c>1</c> for uncompressed surfaces. <c>4</c> for compressed surfaces.
	uint32_t m_width;                  ///< The width of the surface, expressed as a number of texels.
	uint32_t m_height;                 ///< The height of the surface, expressed as a number of texels.
	uint32_t m_depth;                  ///< The depth of the surface, expressed as a number of texels.
	uint32_t m_numFragmentsLog2;       ///< The <c>log2</c> fragments per pixel.
	uint32_t m_numMips;                ///< Up to <c>1+log2(</c><i>max element dimension</i><c>)</c>. Can be fewer than necessary.
	uint32_t m_numSlices;              ///< Number of slices in a surface array.
	bool m_pipeAligned;                ///< A value of <c>true</c> indicates that the metadata is pipe-aligned.
};

/**
 * @brief Describes a surface mip level. Usually populated as part of a SurfaceSummary computed from a SurfaceDescription.
 *
 * @sa computeSurfaceSummary()
 */
struct MipInfo
{
	uint32_t m_width;         ///< The unpadded width, expressed as a number of elements.
	uint32_t m_height;        ///< The unpadded height, expressed as a number of elements.
	uint32_t m_depth;         ///< The unpadded depth, expressed as a number of elements.
	uint32_t m_paddedWidth;   ///< The block-padded width, expressed as a number of elements.
	uint32_t m_paddedHeight;  ///< The block-padded height, expressed as a number of elements.
	uint32_t m_paddedDepth;   ///< The block-padded depth, expressed as a number of elements.
	uint64_t m_offsetInBytes; ///< The byte offset from the beginning of a block slice to this mip level.
	uint64_t m_sizeInBytes;   ///< The number of bytes occupied by blocks that contain this mip level.
	uint32_t m_mipTailCoordX; ///< If this mip level is in the mip tail, element X coordinate of this mip level in the tail block; otherwise, this member is unused.
	uint32_t m_mipTailCoordY; ///< If this mip level is in the mip tail, element Y coordinate of this mip level in the tail block; otherwise, this member is unused. 
};

/**
 * @brief Describes a surface, with block and layout details. Usually computed from a SurfaceDescription.
 *
 * @sa computeSurfaceSummary()
 */
struct SurfaceSummary
{
	SurfaceDescription m_desc;        ///< A copy of the surface description used to generate the summary.
	uint32_t m_numDepthFragmentsLog2; ///< The <c>log2</c> depth fragments per pixel.
	uint32_t m_numColorFragmentsLog2; ///< The <c>log2</c> color fragments per pixel.
	uint32_t m_blockSizeInBytesLog2;  ///< The <c>log2</c> of the size of a block: must be <c>256</c>, <c>4096</c> or <c>65536</c>. The surface in memory is simply a raster of blocks.
	uint32_t m_blockSizeInBytes;      ///< The size of a block: must be <c>256</c>, <c>4096</c> or <c>65536</c>. The surface in memory is simply a raster of blocks.
	size_t m_baseAlign;               ///< The memory alignment required for the surface. Same as block size.
	uint32_t m_firstMipLevelInTail;   ///< The first mip level to appear in the mip tail. If set equal to the mip count, there is no mip tail.
	uint32_t m_blockWidthLog2;        ///< The <c>log2</c> of the block width.
	uint32_t m_blockHeightLog2;       ///< The <c>log2</c> of the block height.
	uint32_t m_blockDepthLog2;        ///< The <c>log2</c> of the block depth.
	uint32_t m_blockWidth;            ///< The width of a block, expressed as a number of elements.
	uint32_t m_blockHeight;           ///< The height of a block, expressed as a number of elements.
	uint32_t m_blockDepth;            ///< The depth of a block, expressed as a number of elements.
	int32_t  m_numBlockSlices;        ///< The count of 2D rasters of blocks. If the block depth is not equal to <c>1</c>, this value is depth rounded up to a multiple of <c><i>m_blockDepth</i></c>.
	uint64_t m_blockSliceSizeInBytes; ///< The number of bytes in one 2D raster of blocks.
	uint64_t m_totalSizeInBytes;      ///< The number of bytes across all 2D rasters of blocks combined.
	MipInfo  m_mips[kMaxMipLevels];   ///< Each MipInfo object in this array provides information about a specific mip level.
};

/**
 * @brief Describes a rectangular region of a render surface.
 *
 * You can use the <c>m_front</c> and <c>m_back</c> members to specify depth for volume surfaces, or to specify fragment index for color fragments. Ranges for depth fragments are not supported.
 */
struct SurfaceRegion
{
	uint32_t m_left;   ///< The x position in elements of the left side of the region. For surface formats with multiple texels per element (such as <c>BCn</c> or <c>4:2:2</c>), specify the value of this member in units of elements, not individual texels.
	uint32_t m_top;    ///< The y position in elements of the top of the region. For surface formats with multiple texels per element (such as <c>BCn</c>), specify the value of this member in units of elements, not individual texels.
	uint32_t m_front;  ///< For volume surfaces, the z position of the front of the region, specified in units of elements. For color MSAA surfaces, pass the first fragment index. For all other surfaces, including depth MSAA, pass <c>0</c>.
	uint32_t m_right;  ///< The x position of the right side of the region, specified in units of elements. For surface formats with multiple texels per element (such as <c>BCn</c> or <c>4:2:2</c>), specify the value of this member in units of elements, not individual texels. The element at <i>x=m_right</i> is not included in the region.
	uint32_t m_bottom; ///< The y position of the bottom of the region, specified in units of elements. For surface formats with multiple texels per element (such as <c>BCn</c>), specify the value of this member in units of elements, not individual texels. The element at <i>y=m_bottom</i> is not included in the region.
	uint32_t m_back;   ///< For volume surfaces, the z position of the back of the region, specified in units of elements. For color MSAA surfaces, pass the last fragment index. For all other surfaces, including depth MSAA, pass <c>1</c>. The element at <i>z=m_back</i> is not included in the region.
};

/**
 * @brief Describes one mip level of a CMASK resource.
 */
struct CmaskMipInfo
{
	uint32_t m_offsetInBytes;    ///< The metadata offset within one slice. The thickness of a slice is <c>1</c>, even for volume depth surfaces.
	uint32_t m_sliceSizeInBytes; ///< The metadata size within one slice. The thickness of a slice is <c>1</c>, even for volume depth surfaces.
};

/**
 * @brief Describes one mip level of an HTILE resource.
 */
struct HtileMipInfo
{
	uint32_t m_offsetInBytes;    ///< The metadata offset within one slice. The thickness of a slice is <c>1</c>, even for volume depth surfaces.
	uint32_t m_sliceSizeInBytes; ///< The metadata size within one slice. The thickness of a slice is <c>1</c>, even for volume depth surfaces.
};

/**
 * @brief Describes one mip level of a DCC resource.
 */
struct DccMipInfo
{
	uint32_t m_offsetInBytes;    ///< The metadata offset within one slice. The thickness of a slice is <c>1</c>, even for volume color surfaces.
	uint32_t m_sliceSizeInBytes; ///< The metadata size within one slice. The thickness of a slice is <c>1</c>, even for volume color surfaces.
};

/**
 * @brief Describes a CMASK resource. Usually computed.
 *
 * @sa computeCmaskInfo(), tileCmaskBuffer(), detileCmaskBuffer()
 */
struct CmaskInfo
{
	uint32_t m_numMips;                    ///< Up to <c>1+log2(</c><i>max element dimension</i><c>)</c>. Can be fewer than necessary.
	uint32_t m_firstMipLevelInTail;        ///< The first mip level to appear in the mip tail. If set equal to the mip count, there is no mip tail.
	uint32_t m_paddedWidth;                ///< Pitch of the color surface, expressed as a number of pixels. This value is greater than or equal to the original width.
	uint32_t m_paddedHeight;               ///< Height of the color surface, expressed as a number of pixels. This value is greater than or equal to the original height.
	size_t m_baseAlign;                    ///< The memory alignment that the CMASK buffer requires.
	uint32_t m_sliceSizeInBytes;           ///< The number of bytes that a slice of the CMASK buffer requires.
	uint32_t m_totalSizeInBytes;           ///< The number of bytes that the entire CMASK buffer requires.
	uint32_t m_metaBlockWidthLog2;         ///< The <c>log2</c> of the meta block width.
	uint32_t m_metaBlockHeightLog2;        ///< The <c>log2</c> of the meta block height.
	uint32_t m_numBlocksPerMetaBlockSlice; ///< The number of meta blocks within one meta block slice.
	CmaskBitLayout m_bitLayout;            ///< Within a nybble, the layout of bits that represent clear regions of a tile.
	CmaskMipInfo m_metaMips[kMaxMipLevels]; ///< Information about specific CMASK mip levels, accessed as <c><i>m_metaMips</i>[<i>N</i>]</c>, in which <c><i>N</i> < kMaxMipLevels</c>.
};

/**
 * @brief Describes an HTILE resource. Usually computed.
 *
 * @sa computeHtileInfo(), tileHtileBuffer(), detileHtileBuffer()
 */
struct HtileInfo
{
	uint32_t m_numDepthFragmentsLog2;       ///< The <c>log2</c> depth fragments per pixel.
	uint32_t m_numMips;                     ///< Up to <c>1+log2</c>(<i>max element dimension</i>). Can be fewer than necessary.
	uint32_t m_firstMipLevelInTail;         ///< The first mip level to appear in the mip tail. If set equal to the mip count, there is no mip tail.
	uint32_t m_paddedWidth;                 ///< Pitch of the depth surface, expressed as a number of pixels. This value is greater than or equal to the original width.
	uint32_t m_paddedHeight;                ///< Height of the depth surface, expressed as a number of pixels. This value is greater than or equal to the original height.
	size_t m_baseAlign;                     ///< The memory alignment that the HTILE buffer requires.
	uint32_t m_sliceSizeInBytes;            ///< The number of bytes that a slice of the HTILE buffer requires.
	uint32_t m_totalSizeInBytes;            ///< The number of bytes that the entire HTILE buffer requires.
	uint32_t m_metaBlockWidthLog2;          ///< The <c>log2</c> of the meta block width.
	uint32_t m_metaBlockHeightLog2;         ///< The <c>log2</c> of the meta block height.
	uint32_t m_numBlocksPerMetaBlockSlice;  ///< The number of meta blocks within one meta block slice.
	HtileMipInfo m_metaMips[kMaxMipLevels]; ///< Information about specific HTILE mip levels, accessed as <c><i>m_metaMips</i>[<i>N</i>]</c>, in which <c><i>N</i> < kMaxMipLevels</c>.
};

/**
 * @brief Describes a DCC resource. Usually computed.
 *
 * @sa computeDccInfo(), tileDccBuffer(), detileDccBuffer()
 */
struct DccInfo
{
	bool m_pipeAligned;                    ///< A value of <c>true</c> indicates that the metadata is pipe-aligned.
	TileMode m_tileMode;                   ///< The tile mode that hardware uses to shuffle and mix address bits in order to increase memory performance.
	SurfaceDimension m_dimension;          ///< The dimensionality of the surface (1D, 2D, 3D).
	uint32_t m_bytesPerElementLog2;        ///< The <c>log2</c> bytes per texel for uncompressed surfaces; <c>log2</c> bytes per block for compressed surfaces.
	uint32_t m_numColorFragmentsLog2;      ///< The <c>log2</c> color fragments per pixel.
	uint32_t m_numMips;                    ///< Up to <c>1+log2(</c><i>max element dimension</i><c>)</c>. Can be fewer than necessary.
	uint32_t m_firstMipLevelInTail;        ///< The first mip level to appear in the mip tail. If set equal to the mip count, there is no mip tail.
	uint32_t m_paddedWidth;                ///< Pitch of the color surface, expressed as a number of pixels. The size is greater than or equal to the original width.
	uint32_t m_paddedHeight;               ///< Height of the color surface, expressed as a number of pixels. The size is greater than or equal to the original height.
	uint32_t m_paddedDepth;                ///< Depth of the color surface, expressed as a number of pixels. The size is greater than or equal to the original depth.
	size_t m_baseAlign;                    ///< The memory alignment that the DCC key buffer requires.
	uint32_t m_sliceSizeInBytes;           ///< The number of bytes that a slice of the DCC key buffer requires.
	uint32_t m_totalSizeInBytes;           ///< The number of bytes that the entire DCC key buffer requires.
	uint32_t m_metaBlockWidthLog2;         ///< The <c>log2</c> of the meta block width.
	uint32_t m_metaBlockHeightLog2;        ///< The <c>log2</c> of the meta block height.
	uint32_t m_numBlocksPerMetaBlockSlice; ///< The number of meta blocks within one meta block slice.
	uint32_t m_mipTailOffsetX;			   ///< X offset of the first level in the mip tail.
	uint32_t m_mipTailOffsetY;			   ///< Y offset of the first level in the mip tail.
	DccMipInfo m_metaMips[kMaxMipLevels];  ///< Information about specific DCC mip levels, accessed as <c><i>m_metaMips</i>[<i>N</i>]</c>, in which <c><i>N</i> < kMaxMipLevels</c>.
};

/**
 * @brief Computes the maximum number of mip levels that a surface can have.
 *
 * @param[in] width  The width of the surface, expressed as a number of texels.
 * @param[in] height The height of the surface, expressed as a number of texels.
 * @param[in] depth  The depth of the surface, expressed as a number of texels.
 *
 * @return           The maximum count of mip levels.
 *
 * @sa SurfaceDescription
 */
/**
 * @brief Validates the specified surface description against hardware restrictions.
 *
 * @param[in] desc The surface description to validate.
 *
 * @return         A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status validateSurfaceDescription(const SurfaceDescription *desc);

/**
 * @brief Computes a detailed summary of surface information given a light description.
 *
 * @param[out] summary The computed summary.
 * @param[in] desc     The surface description.
 *
 * @return             A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeSurfaceSummary(SurfaceSummary *summary, const SurfaceDescription *desc);

/**
 * @brief Computes the size of an untiled buffer that can hold a given surface.
 *
 * @param[out] outSize Receives the required size of the untiled surface if the operation was successful.
 * @param[in] summary  A computed summary of the surface.
 * @param[in] mipLevel Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 *
 * @return             A status code from AgcGpuAddress::Status.
 *
 * @sa computeSurfaceSummary()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeForSurface(unsigned long *outSize, const SurfaceSummary *summary, uint32_t mipLevel);

/**
 * @brief Computes the size of an untiled buffer that can hold a given surface region.
 *
 * @param[out] outSize Receives the required size of the untiled surface if the operation was successful.
 * @param[in] summary  A computed summary of the surface.
 * @param[in] region   Describes the bounds of the region in the destination surface to which this function writes tiled data.
 * @param[in] mipLevel Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 *
 * @return                A status code from AgcGpuAddress::Status.
 *
 * @sa computeSurfaceSummary()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeForSurfaceRegion(uint64_t *outSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel);

/**
 * @brief Computes the size of an untiled buffer that can hold a given surface if the destination needs padding.
 *
 * @param[out] outSize          Receives the required size of the untiled surface if the operation was successful.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] untiledRowPitch   The padded width of an untiled row in elements. If you have a choice, don't make row pitch more than the width.
 * @param[in] untiledSlicePitch The padded width times height of an untiled row in elements. If you have a choice, don't make slice pitch more than the area.
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa computeSurfaceSummary()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeWithPaddingForSurface(uint64_t *outSize, const SurfaceSummary *summary, uint32_t mipLevel, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Computes the size of an untiled buffer that can hold a given surface region if the destination needs padding.
 *
 * @param[out] outSize          Receives the required size of the untiled surface if the operation was successful.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] region            Describes the bounds of the region in the destination surface to which this function writes tiled data.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] untiledRowPitch   The padded width of an untiled row in elements. If you have a choice, don't make row pitch more than the width.
 * @param[in] untiledSlicePitch The padded width times height of an untiled row in elements. If you have a choice, don't make slice pitch more than the area.
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa computeSurfaceSummary()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeWithPaddingForSurfaceRegion(uint64_t *outSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Tiles a surface.
 *
 * Processes a single mip level only.
 *
 * @param[out] outSurfaceData The data address of the target surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize     The size of <c><i>outSurfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] untiled         Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize     The size of <c><i>untiled</i></c>. Use computeUntiledSizeForSurface() to determine how much data this function will read.
 * @param[in] summary         A computed summary of the surface.
 * @param[in] mipLevel        Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                            For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                    A status code from AgcGpuAddress::Status.
 *
 * @sa detileSurface()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileSurface(void *__restrict outSurfaceData, unsigned long surfaceSize, const void *__restrict untiled, unsigned long untiledSize, const SurfaceSummary *summary, uint32_t mipLevel, uint32_t arraySlice);

/**
 * @brief Tiles a subregion of a surface.
 *
 * Processes a single mip level only.
 *
 * @param[out] outSurfaceData The data address of the target surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize     The size of <c><i>outSurfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] untiled         Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize     The size of <c><i>untiled</i></c>. Use computeUntiledSizeForSurfaceRegion() to determine how much data this function will read.
 * @param[in] summary         A computed summary of the surface.
 * @param[in] region          Describes the bounds of the region in the destination surface to which this function writes tiled data.
 * @param[in] mipLevel        Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                            For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                    A status code from AgcGpuAddress::Status.
 *
 * @sa detileSurfaceRegion()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileSurfaceRegion(void *__restrict outSurfaceData, uint64_t surfaceSize, const void *__restrict untiled, uint64_t untiledSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel, uint32_t arraySlice);

/**
 * @brief Tiles a surface from a padded buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outSurfaceData   The data address of the target surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize       The size of <c><i>outSurfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] untiled           Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize       The size of <c><i>untiled</i></c>. Use computeUntiledSizeWithPaddingForSurface() to determine how much data this function will read.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                              For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] untiledRowPitch   The pitch of the <c><i>untiled</i></c> data, specified in elements. The value must be at least as large as the width of the mip level.
 * @param[in] untiledSlicePitch The size of one Z-slice of the <c><i>untiled</i></c> data, specified in elements. This value must be at least as large as the width of the mip level multiplied by its height.
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa detileSurfaceToPaddedBuffer()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileSurfaceFromPaddedBuffer(void *__restrict outSurfaceData, uint64_t surfaceSize, const void *__restrict untiled, uint64_t untiledSize, const SurfaceSummary *summary, uint32_t mipLevel, uint32_t arraySlice, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Tiles a subregion of a surface from a padded buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outSurfaceData   The data address of the target surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize       The size of <c><i>outSurfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] untiled           Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize       The size of <c><i>untiled</i></c>. Use computeUntiledSizeWithPaddingForSurfaceRegion() to determine how much data this function will read.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] region            Describes the bounds of the region in the destination surface to which this function writes tiled data.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                              For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] untiledRowPitch   The pitch of the <c><i>untiled</i></c> data, specified as a number of elements. The value must be at least as large as the width (right-left) of the <c><i>region</i></c> argument.
 * @param[in] untiledSlicePitch The size of one Z-slice of the <c><i>untiled</i></c> data, specified as a number of elements. This value must be at least as large as the width (right-left) of the <c><i>region</i></c> argument multiplied by its height (bottom-top).
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa detileSurfaceRegionToPaddedBuffer()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileSurfaceRegionFromPaddedBuffer(void *__restrict outSurfaceData, uint64_t surfaceSize, const void *__restrict untiled, uint64_t untiledSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel, uint32_t arraySlice, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Detiles a surface.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled The destination buffer that is to receive the untiled surface data.
 * @param[in] untiledSize The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForSurface() to determine how much data this function will write.
 * @param[in] surfaceData The data address of the source surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize The size of <c><i>surfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] summary     A computed summary of the surface.
 * @param[in] mipLevel    Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice  For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                        For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 *
 * @sa tileSurface()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileSurface(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict surfaceData, uint64_t surfaceSize, const SurfaceSummary *summary, uint32_t mipLevel, uint32_t arraySlice);

/**
 * @brief Detiles a subregion of a surface.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled The destination buffer that is to receive the untiled surface data.
 * @param[in] untiledSize The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForSurfaceRegion() to determine how much data this function will write.
 * @param[in] surfaceData The data address of the source surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize The size of <c><i>surfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] summary     A computed summary of the surface.
 * @param[in] region      Describes the bounds of the region in the source surface from which this function reads tiled data.
 * @param[in] mipLevel    Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice  For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                        For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 *
 * @sa tileSurfaceRegion()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileSurfaceRegion(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict surfaceData, uint64_t surfaceSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel, uint32_t arraySlice);

/**
 * @brief Detiles a surface to a padded buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled       The destination buffer that is to receive the untiled surface data.
 * @param[in] untiledSize       The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeWithPaddingForSurface() to determine how much data this function will write.
 * @param[in] surfaceData       The data address of the source surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize       The size of <c><i>surfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                              For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] untiledRowPitch   The pitch of the <c><i>outUntiled</i></c> data, specified in elements. The value must be at least as large as the width of the mip level.
 * @param[in] untiledSlicePitch The size of one Z-slice of the <c><i>outUntiled</i></c> data, specified in elements. This value must be at least as large as the width of the mip level multiplied by its height.
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa tileSurfaceFromPaddedBuffer()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileSurfaceToPaddedBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict surfaceData, uint64_t surfaceSize, const SurfaceSummary *summary, uint32_t mipLevel, uint32_t arraySlice, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Detiles a subregion of a surface to a padded buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled       The destination buffer that is to receive the untiled surface data.
 * @param[in] untiledSize       The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeWithPaddingForSurfaceRegion() to determine how much data this function will write.
 * @param[in] surfaceData       The data address of the source surface. Do not perform any offset calculations on this address.
 * @param[in] surfaceSize       The size of <c><i>surfaceData</i></c>. The expected value is SurfaceSummary::m_totalSizeInBytes.
 * @param[in] summary           A computed summary of the surface.
 * @param[in] region            Describes the bounds of the region in the source surface from which this function reads tiled data.
 * @param[in] mipLevel          Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                              For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] untiledRowPitch   The pitch of the <c><i>outUntiled</i></c> data, specified in elements. The value must be at least as large as the width (right-left) of the <c><i>region</i></c> argument.
 * @param[in] untiledSlicePitch The size of one Z-slice of the <c><i>outUntiled</i></c> data, specified in elements. This value must be at least as large as the width (right-left) of the <c><i>region</i></c> argument multiplied by its height (bottom-top).
 *
 * @return                      A status code from AgcGpuAddress::Status.
 *
 * @sa tileSurfaceRegionFromPaddedBuffer()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileSurfaceRegionToPaddedBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict surfaceData, uint64_t surfaceSize, const SurfaceSummary *summary, const SurfaceRegion *region, uint32_t mipLevel, uint32_t arraySlice, uint32_t untiledRowPitch, uint64_t untiledSlicePitch);

/**
 * @brief Computes the tiled byte offset for the specified element in a surface.
 *
 * Note that this function is <i>not</i> optimized for repeat calls. To convert an entire surface between
 * tiled and untiled formats, use the tiling functions instead.
 *
 * @param[out] outTiledByteOffset Receives the byte offset of the specified element in a tiled surface buffer. This pointer must not be <c>NULL</c>.
 * @param[in] summary             A computed summary of the surface.
 * @param[in] x                   The X-coordinate of the element to locate. For surface formats with multiple texels per element, specify this value in units of elements, not individual texels.
 * @param[in] y                   The Y-coordinate of the element to locate. For surface formats with multiple texels per element, specify this value in units of elements, not individual texels.
 * @param[in] z                   The Z-coordinate of the element to locate. For non-volume surfaces, pass <c>0</c>.
 * @param[in] fragmentIndex       The index of the sub-pixel fragment to locate. For non-MSAA surfaces, pass <c>0</c>.
 * @param[in] mipLevel            Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] arraySlice          For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                                For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                        A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeTiledElementByteOffset(uint64_t *outTiledByteOffset, const SurfaceSummary *summary, uint32_t x, uint32_t y, uint32_t z, uint32_t fragmentIndex, uint32_t mipLevel, uint32_t arraySlice);

////////////////////////////////////////////////////////////
// Metadata functions, mainly for Agc use
////////////////////////////////////////////////////////////

/**
 * @brief Determines CMASK information according to various hardware rules.
 *
 * @param[out] info   The computed CMASK information.
 * @param[in] summary A computed summary of the surface.
 *
 * @return            A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeCmaskInfo(CmaskInfo *info, const SurfaceSummary *summary);

/**
 * @brief Determines HTILE information according to various hardware rules.
 *
 * @param[out] info   The computed HTILE information.
 * @param[in] summary A computed summary of the surface.
 *
 * @return            A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeHtileInfo(HtileInfo *info, const SurfaceSummary *summary);

/**
 * @brief Determines DCC information according to various hardware rules.
 *
 * @param[out] info   The computed DCC information.
 * @param[in] summary A computed summary of the surface.
 *
 * @return            A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeDccInfo(DccInfo *info, const SurfaceSummary *summary);

/**
 * @brief Computes the size of an untiled buffer that can hold a given CMASK buffer.
 *
 * @param[out] outSize Receives the required size of the untiled buffer if the operation was successful.
 * @param[in] info     The computed CMASK information.
 *
 * @return             A status code from AgcGpuAddress::Status.
 *
 * @sa computeCmaskInfo()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeForCmaskBuffer(uint64_t *outSize, const CmaskInfo *info);

/**
 * @brief Computes the size of an untiled buffer that can hold a given HTILE buffer.
 *
 * @param[out] outSize Receives the required size of the untiled buffer if the operation was successful.
 * @param[in] info     The computed HTILE information.
 *
 * @return             A status code from AgcGpuAddress::Status.
 *
 * @sa computeHtileInfo()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeForHtileBuffer(uint64_t *outSize, const HtileInfo *info);

/**
 * @brief Computes the size of an untiled buffer that can hold a given DCC buffer.
 *
 * @param[out] outSize Receives the required size of the untiled buffer if the operation was successful.
 * @param[in] info     The computed DCC information.
 * @param[in] mipLevel Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 *
 * @return             A status code from AgcGpuAddress::Status.
 *
 * @sa computeDccInfo()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeUntiledSizeForDccBuffer(uint64_t *outSize, const DccInfo *info, uint32_t mipLevel);

/**
 * @brief Tiles a CMASK buffer.
 *
 * @param[out] outMetadata The address of the target CMASK buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>outMetadata</i></c>. The expected value is CmaskInfo::m_totalSizeInBytes.
 * @param[in] untiled      Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize  The size of <c><i>untiled</i></c>. Use computeUntiledSizeForCmaskBuffer() to determine how much data this function will read.
 * @param[in] info         The computed CMASK information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                         For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileCmaskBuffer(void *__restrict outMetadata, uint64_t metadataSize, const void *__restrict untiled, uint64_t untiledSize, const CmaskInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Tiles an HTILE buffer.
 *
 * @param[out] outMetadata The address of the target HTILE buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>outMetadata</i></c>. The expected value is HtileInfo::m_totalSizeInBytes.
 * @param[in] untiled      Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize  The size of <c><i>untiled</i></c>. Use computeUntiledSizeForHtileBuffer() to determine how much data this function will read.
 * @param[in] info         The computed HTILE information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                         For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileHtileBuffer(void *__restrict outMetadata, uint64_t metadataSize, const void *__restrict untiled, uint64_t untiledSize, const HtileInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Tiles a DCC buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outMetadata The address of the target DCC buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>outMetadata</i></c>. The expected value is DccInfo::m_totalSizeInBytes.
 * @param[in] untiled      Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize  The size of <c><i>untiled</i></c>. Use computeUntiledSizeForDccBuffer() to determine how much data this function will read.
 * @param[in] info         The computed DCC information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_ADDRESS_DEPRECATED_MSG("tileDccBuffer requires a framgent index")
SCE_AGC_GPU_ADDRESS_EXPORT Status tileDccBuffer(void *__restrict outMetadata, uint64_t metadataSize, const void *__restrict untiled, uint64_t untiledSize, const DccInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Tiles a DCC buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outMetadata The address of the target DCC buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>outMetadata</i></c>. The expected value is DccInfo::m_totalSizeInBytes.
 * @param[in] untiled      Pointer to the source untiled surface data that this function reads.
 * @param[in] untiledSize  The size of <c><i>untiled</i></c>. Use computeUntiledSizeForDccBuffer() to determine how much data this function will read.
 * @param[in] info         The computed DCC information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] fragment	   For MSAA surface pass the fragment index otherwise pass 0. DCC only compresses first two fragments.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status tileDccBuffer(void *__restrict outMetadata, uint64_t metadataSize, const void *__restrict untiled, uint64_t untiledSize, const DccInfo *info, uint32_t mipLevel, uint32_t slice, uint32_t fragment);

/**
 * @brief Detiles a CMASK buffer.
 *
 * @param[out] outUntiled  The destination buffer that is to receive the untiled data.
 * @param[in] untiledSize  The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForCmaskBuffer() to determine how much data this function will write.
 * @param[in] metadata     The address of the source-CMASK buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>metadata</i></c>. The expected value is CmaskInfo::m_totalSizeInBytes.
 * @param[in] info         The computed CMASK information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                         For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return                 A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileCmaskBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict metadata, uint64_t metadataSize, const CmaskInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Detiles an HTILE buffer.
 *
 * @param[out] outUntiled  The destination buffer that is to receive the untiled data.
 * @param[in] untiledSize  The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForHtileBuffer() to determine how much data this function will write.
 * @param[in] metadata     The address of the source-HTILE buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>metadata</i></c>. The expected value is HtileInfo::m_totalSizeInBytes.
 * @param[in] info         The computed HTILE information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                         For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return                 A status code from AgcGpuAddress::Status.
 */

SCE_AGC_GPU_ADDRESS_EXPORT Status detileHtileBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict metadata, uint64_t metadataSize, const HtileInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Detiles a DCC buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled  The destination buffer that is to receive the untiled data.
 * @param[in] untiledSize  The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForDccBuffer() to determine how much data this function will write.
 * @param[in] metadata     The address of the source-DCC buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>metadata</i></c>. The expected value is DccInfo::m_totalSizeInBytes.
 * @param[in] info         The computed DCC information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_ADDRESS_DEPRECATED_MSG("detileDccBuffer requires a framgent index")
SCE_AGC_GPU_ADDRESS_EXPORT Status detileDccBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict metadata, uint64_t metadataSize, const DccInfo *info, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Detiles a DCC buffer.
 *
 * Processes a single mip level only.
 *
 * @param[out] outUntiled  The destination buffer that is to receive the untiled data.
 * @param[in] untiledSize  The size of <c><i>outUntiled</i></c>. Use computeUntiledSizeForDccBuffer() to determine how much data this function will write.
 * @param[in] metadata     The address of the source-DCC buffer. Do not perform any offset calculations on this address.
 * @param[in] metadataSize The size of <c><i>metadata</i></c>. The expected value is DccInfo::m_totalSizeInBytes.
 * @param[in] info         The computed DCC information.
 * @param[in] mipLevel     Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice        For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                         For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 * @param[in] fragment	   For MSAA surface pass the fragment index otherwise pass 0. DCC only compresses first two fragments.
 *
 * @return                A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status detileDccBuffer(void *__restrict outUntiled, uint64_t untiledSize, const void *__restrict metadata, uint64_t metadataSize, const DccInfo *info, uint32_t mipLevel, uint32_t slice, uint32_t fragment);

/**
 * @brief Computes the byte offset for an element (tile) of a CMASK surface.
 *
 * @param[out] outOffset Receives the nybble offset for an element (tile) of a CMASK surface if the operation was successful. The byte offset is shifted left by one and the LSB indicates the nybble that contains the tile. A value of <c>0</c> indicates the tile in the first nybble, and a value of <c>1</c> indicates the tile in the second nybble.
 * @param[in] info       The computed CMASK information.
 * @param[in] tileX      The X-coordinate of the tile to locate.
 * @param[in] tileY      The Y-coordinate of the tile to locate.
 * @param[in] mipLevel   Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                       For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                       For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return               A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeCmaskBufferNybbleOffset(uint64_t *outOffset, const CmaskInfo *info, uint32_t tileX, uint32_t tileY, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Computes the byte offset for an element (tile) of an HTILE surface.
 *
 * @param[out] outOffset Receives the byte offset for an element (tile) of an HTILE surface if the operation was successful.
 * @param[in] info       The computed HTILE information.
 * @param[in] tileX      The X-coordinate of the tile to locate.
 * @param[in] tileY      The Y-coordinate of the tile to locate.
 * @param[in] mipLevel   Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                       For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index.
 *                       For volume surfaces, pass the depth index. For all other surfaces, pass <c>0</c>.
 *
 * @return               A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeHtileBufferByteOffset(uint64_t *outOffset, const HtileInfo *info, uint32_t tileX, uint32_t tileY, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Computes the byte offset for an element (8-bit key) of a DCC buffer, which corresponds to 256 bytes of a surface. This 256-byte chunk does not form the shape of a tile for surfaces with 1-byte, or 2-byte elements.
 *
 * @param[out] outOffset Receives the byte offset for an element of a DCC key buffer if the operation was successful.
 * @param[in] info       The computed DCC information.
 * @param[in] x          The X-coordinates on the surface corresponding to the DCC key. Many X-Y pairs will map to the same key.
 * @param[in] y          The Y-coordinates on the surface corresponding to the DCC key. Many X-Y pairs will map to the same key.
 * @param[in] mipLevel   Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                       For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 *
 * @return               A status code from AgcGpuAddress::Status.
 */
SCE_AGC_ADDRESS_DEPRECATED_MSG("computeDccBufferByteOffset requires a fragment index")
SCE_AGC_GPU_ADDRESS_EXPORT Status computeDccBufferByteOffset(uint64_t *outOffset, const DccInfo *info, uint32_t x, uint32_t y, uint32_t mipLevel, uint32_t slice);

/**
 * @brief Computes the byte offset for an element (8-bit key) of a DCC buffer, which corresponds to 256 bytes of a surface. This 256-byte chunk does not form the shape of a tile for surfaces with 1-byte, or 2-byte elements.
 *
 * @param[out] outOffset Receives the byte offset for an element of a DCC key buffer if the operation was successful.
 * @param[in] info       The computed DCC information.
 * @param[in] x          The X-coordinates on the surface corresponding to the DCC key. Many X-Y pairs will map to the same key.
 * @param[in] y          The Y-coordinates on the surface corresponding to the DCC key. Many X-Y pairs will map to the same key.
 * @param[in] fragment	 The fragment index for an MSAA surface. Only first two fragments can be compressed with DCC.
 * @param[in] mipLevel   Index of the mip level to query. A value of <c>0</c> corresponds to the base level (the largest mip level).
 * @param[in] slice      For surface arrays, pass the array index of the query. For cubemaps, pass the index of the requested face: +x = <c>0</c>, -x = <c>1</c>, +y = <c>2</c>, -y = <c>3</c>, +z = <c>4</c>, -z = <c>5</c>.
 *                       For cubemap arrays, pass <c><i>N</i>*6+<i>F</i></c>, in which <c><i>N</i></c> is the cubemap index and <c><i>F</i></c> is the face index. For all other surfaces, pass <c>0</c>.
 
 *
 * @return               A status code from AgcGpuAddress::Status.
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeDccBufferByteOffset(uint64_t *outOffset, const DccInfo *info, uint32_t x, uint32_t y, uint32_t fragment, uint32_t mipLevel, uint32_t slice);

/////////////////////////////////////////////////////////
// Buffer swizzling functions
/////////////////////////////////////////////////////////

/**
 * @brief Computes the size of a swizzled buffer.
 *
 * A swizzled buffer often requires more space than its linear equivalent, due to extra padding.
 *
 * @param[out] outSizeBytes     Receives the size of the swizzled buffer in bytes if the operation was successful. This pointer must not be <c>NULL</c>.
 * @param[in] recordSizeInBytes The size of a single buffer record, expressed as a number of bytes. Must be divisible by <c>4</c> with no remainder.
 * @param[in] numRecords        The total number of elements in the buffer.
 * @param[in] swizzleStride     The number of consecutive buffer records to swizzle in a block from AoS to SoA. For maximum performance, the product of the <c><i>swizzleStride</i></c> and swizzle size <c>(4)</c> should be an exact multiple of the cache-line size (64 bytes).
 *
 * @return                       A status code from AgcGpuAddress::Status.
 *
 * @sa Agc::Core::Buffer::setSwizzle()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status computeSwizzledBufferSize(uint64_t *outSizeBytes, uint32_t recordSizeInBytes, uint32_t numRecords, BufferSwizzleStride swizzleStride);

/**
 * @brief Converts buffer data from linear format to element-level swizzled format.
 *
 * @param[out] outSwizzledData   Receives the swizzled data. Use the computeSwizzledBufferSize() function to determine the minimum required buffer size. The data must not overlap <c><i>linearData</i></c>, and this pointer must not be <c>NULL</c>.
 * @param[in] swizzledBufferSize The size in bytes of <c><i>outSwizzledData</i></c>.
 * @param[in] linearData         Pointer from which this function reads source linear data. The amount of data that will be read is <c><i>recordSizeInBytes</i></c>*<c><i>numRecords</i></c> bytes. The data must not overlap <c><i>outSwizzledData</i></c>, and this pointer must not be <c>NULL</c>.
 * @param[in] linearBufferSize   The size in bytes of <c><i>linearData</i></c>.
 * @param[in] recordSizeInBytes  The size of a single buffer record, expressed as a number of bytes. Must be divisible by <c>4</c> with no remainder.
 * @param[in] numRecords         The number of records in the buffer.
 * @param[in] swizzleStride      The number of consecutive buffer records that <c><i>outSwizzledData</i></c> swizzled together in a block from AoS to SoA, as reported by sce::Agc::Core::Buffer::getIndexStride(). For maximum performance, the product of the <c><i>swizzleStride</i></c> and the swizzle size <c>(4)</c> should be an exact multiple of the cache-line size (64 bytes).
 *
 * @return                     A status code from AgcGpuAddress::Status.
 *
 * @sa Agc::Core::Buffer::setIndexStride(), computeSwizzledBufferSize(), deswizzleBufferData()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status swizzleBufferData(void *__restrict outSwizzledData, uint64_t swizzledBufferSize, const void *__restrict linearData, uint64_t linearBufferSize, uint32_t recordSizeInBytes, uint32_t numRecords, BufferSwizzleStride swizzleStride);

/**
 * @brief Converts buffer data from element-level swizzled format to linear format.
 *
 * @param[out] outLinearData     Receives the linear data. The buffer must be sufficient to receive <c><i>recordSizeInBytes</i></c>*<c><i>numRecords</i></c> bytes of data. The data must not overlap <c><i>swizzledData</i></c>, and this pointer must not be <c>NULL</c>.
 * @param[in] linearBufferSize   The size in bytes of <c><i>outLinearData</i></c>.
 * @param[in] swizzledData       Pointer from which this function reads source swizzled data. Use the computeSwizzledBufferSize() function to determine the amount of data that will be read. The data must not overlap <c><i>outLinearData</i></c>, and this pointer must not be <c>NULL</c>.
 * @param[in] swizzledBufferSize The size in bytes of <c><i>swizzledData</i></c>.
 * @param[in] recordSizeInBytes  The size of a single buffer record, expressed as a number of bytes. Must be divisible by <c>4</c> with no remainder.
 * @param[in] numRecords         The number of records in the buffer.
 * @param[in] swizzleStride      The number of consecutive buffer records that <c><i>swizzledData</i></c> swizzled together in a block from AoS to SoA, as reported by sce::Agc::Core::Buffer::getIndexStride(). For maximum performance, the product of the <c><i>swizzleStride</i></c> and the swizzle size <c>(4)</c> should be an exact multiple of the cache-line size (64 bytes).
 *
 * @return                   A status code from AgcGpuAddress::Status.
 *
 * @sa Agc::Core::Buffer::setIndexStride(), computeSwizzledBufferSize(), swizzleBufferData()
 */
SCE_AGC_GPU_ADDRESS_EXPORT Status deswizzleBufferData(void *__restrict outLinearData, uint64_t linearBufferSize, const void *__restrict swizzledData, uint64_t swizzledBufferSize, uint32_t recordSizeInBytes, uint32_t numRecords, BufferSwizzleStride swizzleStride);

} }
