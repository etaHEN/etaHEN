#pragma once

#include <util.hpp>

static constexpr uint32_t hash(const StringView &str) {
	uint32_t hash = 0;
	for (size_t i = 0; i < str.length(); i++) {
		hash = 31 * hash + (str[i] & 0xff); // NOLINT(*)
	}
	return hash;
}

struct HashedStringView : StringView {
	uint32_t hash;

	constexpr HashedStringView() : StringView(), hash() {}
	explicit constexpr HashedStringView(const StringView &name) : StringView(name), hash(::hash(name)) {}

	constexpr int32_t operator<=>(const HashedStringView &rhs) const {
		const int32_t v = (int32_t)(hash - rhs.hash);
		return v != 0 ? v : StringView::operator<=>(rhs);
	}
};

struct SysmoduleMapEntry {
	HashedStringView name;
	uint32_t id;

	constexpr SysmoduleMapEntry() : name(), id() {};
	constexpr SysmoduleMapEntry(const StringView &name, uint32_t id) : name(name), id(id) {}

	constexpr int32_t operator<=>(const SysmoduleMapEntry &rhs) const {
		const int32_t v = (int32_t)(name.hash - rhs.name.hash);
		return v != 0 ? v : name <=> rhs.name;
	}
	constexpr int32_t operator<=>(const HashedStringView &rhs) const {
		return name <=> rhs;
	}
};

template <size_t N>
struct SysmoduleMapEntryArray {
	SysmoduleMapEntry array[N];

	constexpr SysmoduleMapEntryArray(const SysmoduleMapEntry (&array)[N]) {
		__builtin_memcpy(this->array, array, sizeof(array));
	}

	constexpr SysmoduleMapEntry &operator[](size_t i) {
		return array[i];
	}

	constexpr const SysmoduleMapEntry &operator[](size_t i) const {
		return array[i];
	}
};

constexpr void swap(SysmoduleMapEntry& lhs, SysmoduleMapEntry& rhs) {
	SysmoduleMapEntry tmp = rhs;
	rhs = lhs;
	lhs = tmp;
}

template <size_t N>
constexpr void doSort(SysmoduleMapEntryArray<N> &array, size_t left, size_t right) {
	if (left < right) {
		size_t m = left;

		for (size_t i = left + 1; i<right; i++) {
			if (array[i]<array[left]) {
				swap(array[++m], array[i]);
			}
		}

		swap(array[left], array[m]);

		doSort(array, left, m);
		doSort(array, m + 1, right);
	}
}

template <size_t N>
constexpr SysmoduleMapEntryArray<N> sort(const SysmoduleMapEntry (&array)[N]) {
	SysmoduleMapEntryArray<N> sorted = array;
	doSort(sorted, 0, N);
	return sorted;
}

template <size_t N>
class SysmoduleHashMap {
	SysmoduleMapEntryArray<N> entries;

	constexpr int_fast32_t getIndex(const HashedStringView &key) const {
		int_fast32_t lo = 0;
		int_fast32_t hi = N - 1;

		while (lo <= hi) {
			const auto m = (lo + hi) >> 1;
			const auto n = entries[m] <=> key;

			if (n == 0) [[unlikely]] {
				return m;
			}

			if (n < 0)
				lo = m + 1;
			else
				hi = m - 1;
		}
		return -(lo + 1);
	}

	public:
		constexpr SysmoduleHashMap(const SysmoduleMapEntry (&array)[N]) : entries{sort(array)} {}
		constexpr uint32_t operator[](const StringView &key) const {
			HashedStringView hashed{key};
			const int_fast32_t index = getIndex(hashed);
			return index >= 0 ? entries[index].id : 0;
		}
};

static constexpr const SysmoduleHashMap SYSMODULES{{
	{"libSceMat"_sv, 0x80000048},
	{"libSceNet"_sv, 0x8000001c},
	{"libSceIpmi"_sv, 0x8000001d},
	{"libSceMbus"_sv, 0x8000001e},
	{"libSceRegMgr"_sv, 0x8000001f},
	{"libSceRtc"_sv, 0x80000020},
	{"libSceAvSetting"_sv, 0x80000021},
	{"libSceVideoOut"_sv, 0x80000022},
	{"libSceAgcDriver"_sv, 0x80000080},
	{"libSceAgc"_sv, 0x80000094},
	{"libSceAudioOut"_sv, 0x80000001},
	{"libSceAudioIn"_sv, 0x80000002},
	{"libSceAjmi"_sv, 0x8000007e},
	{"libSceAjm.native"_sv, 0x80000023},
	{"libScePad"_sv, 0x80000024},
	{"libSceDbg"_sv, 0x80000025},
	{"libSceNetCtl"_sv, 0x80000009},
	{"libSceHttp"_sv, 0x8000000a},
	{"libSceSsl"_sv, 0x8000000b},
	{"libSceNpCommon"_sv, 0x8000000c},
	{"libSceNpManager"_sv, 0x8000000d},
	{"libSceNpWebApi"_sv, 0x8000000e},
	{"libSceSaveData"_sv, 0x8000000f},
	{"libSceSystemService"_sv, 0x80000010},
	{"libSceUserService"_sv, 0x80000011},
	{"libSceCommonDialog"_sv, 0x80000018},
	{"libSceSysUtil"_sv, 0x80000026},
	{"libSceRazorCpu_debug"_sv, 0x80000075},
	{"libSceHttp2"_sv, 0x8000008c},
	{"libSceNpGameIntent"_sv, 0x8000008d},
	{"libSceNpWebApi2"_sv, 0x8000008f},
	{"libSceHttpCache"_sv, 0x80000078},
	{"libSceAmpr"_sv, 0x800000b7},
	{"libSceDipsw"_sv, 0x80000029},
	{"libSceSysCore"_sv, 0x80000004},
	{"libSceGpuTrace"_sv, 0x8000007b},
	{"libSceVdecCore.native"_sv, 0x80000015},
	{"libSceVdecSavc2.native"_sv, 0x80000036},
	{"libSceVdecShevc.native"_sv, 0x8000003c},
	{"libSceGpuCapture"_sv, 0x8000007f},
	{"libSceAc3Enc"_sv, 0x80000013},
	{"libSceDseehx"_sv, 0x80000056},
	{"libSceDtsEnc"_sv, 0x80000028},
	{"libSceOpusCeltDec"_sv, 0x80000044},
	{"libSceOpusCeltEnc"_sv, 0x80000043},
	{"libSceOpusDec"_sv, 0x80000069},
	{"libSceOpusSilkEnc"_sv, 0x80000068},
	{"libSceAudiodecCpuDtsHdMa"_sv, 0x8000002d},
	{"libSceAudiodecCpuLpcm"_sv, 0x8000002e},
	{"libSceAudiodecCpuTrhd"_sv, 0x80000082},
	{"libSceAudioSystem"_sv, 0x80000083},
	{"libSceVenc"_sv, 0x80000084},
	{"libSceAgcVsh"_sv, 0x80000086},
	{"libSceAgcVshDebug"_sv, 0x80000087},
	{"libSceComposite"_sv, 0x8000008a},
	{"libSceCompositeExt"_sv, 0x8000008b},
	{"libSceNgs2"_sv, 0x80000090},
	{"libSceVcodec"_sv, 0x80000091},
	{"libSceSulphaDrv"_sv, 0x8000003b},
	{"libSceAgcResourceRegistration"_sv, 0x80000093},
	{"libScePosixForWebKit"_sv, 0x80000098},
	{"libSceVoiceCommand"_sv, 0x80000099},
	{"libSceEmbeddedTtsCoreG3"_sv, 0x8000009b},
	{"libSceEmbeddedTts"_sv, 0x8000009c},
	{"libSceTEEClient"_sv, 0x800000a2},
	{"libSceVdecSvp9.native"_sv, 0x800000af},
	{"libSceCamera"_sv, 0x8000001a},
	{"libSceLibreSsl3"_sv, 0x800000b8},
	{"libSceLibreSsl"_sv, 0x80000065},
	{"libSceHidControl"_sv, 0x80000017},
	{"libSceFsInternalForVsh"_sv, 0x80000066},
	{"libSceVisionManager"_sv, 0x80000012},
	{"libSceCdlgUtilServer"_sv, 0x80000007},
	{"libSceAppInstUtil"_sv, 0x80000014},
	{"libSceNpSns"_sv, 0x8000001b},
	{"libSceMarlin"_sv, 0x80000027},
	{"libSceBgft"_sv, 0x8000002a},
	{"libScePsm"_sv, 0x80000030},
	{"libSceKbEmulate"_sv, 0x80000031},
	{"libSceAppChecker"_sv, 0x80000032},
	{"libSceBackupRestoreUtil"_sv, 0x8000003f},
	{"libSceLoginMgrServer"_sv, 0x80000045},
	{"libSceVideoOutSecondary"_sv, 0x80000046},
	{"libSceSocialScreen"_sv, 0x800000ae},
	{"libSceDataTransfer"_sv, 0x80000057},
	{"libSceAbstractStorage"_sv, 0x80000058},
	{"libSceImageUtil"_sv, 0x80000059},
	{"libSceMetadataReaderWriter"_sv, 0x8000005a},
	{"libSceJpegParser"_sv, 0x8000005b},
	{"libSceGvMp4Parser"_sv, 0x8000005c},
	{"libScePngParser"_sv, 0x8000005d},
	{"libSceGifParser"_sv, 0x8000005e},
	{"libSceAbstractLocal"_sv, 0x8000005f},
	{"libSceAbstractYoutube"_sv, 0x80000061},
	{"libSceAbstractTwitter"_sv, 0x80000062},
	{"libSceJitBridge"_sv, 0x8000006f},
	{"libSceJscCompiler"_sv, 0x80000070},
	{"libSceOrbisCompat"_sv, 0x80000071},
	{"libSceWeb"_sv, 0x80000072},
	{"libSceWebKit2"_sv, 0x80000073},
	{"libSceWebKit2Secure"_sv, 0x80000074},
	{"libSceRnpsAppMgr"_sv, 0x80000076},
	{"libSceAsyncStorageInternal"_sv, 0x80000077},
	{"libSceNKWeb"_sv, 0x80000079},
	{"libSceNKWebKit"_sv, 0x8000007a},
	{"libSceVnaInternal"_sv, 0x8000007c},
	{"libSceVnaWebsocket"_sv, 0x8000007d},
	{"libSceAvcap2"_sv, 0x80000085},
	{"libSceSystemLogger2NativeQueueClient"_sv, 0x80000088},
	{"libSceSystemLogger2Delivery"_sv, 0x80000089},
	{"libSceShareInternal.native"_sv, 0x8000008e},
	{"libSceResourceArbitrator"_sv, 0x80000092},
	{"libSceMediaFrameworkInterface"_sv, 0x80000095},
	{"libSceSystemTts"_sv, 0x80000097},
	{"libSceNpRemotePlaySessionSignaling"_sv, 0x8000009a},
	{"libSceJemspace"_sv, 0x8000009e},
	{"libSceSystemLogger2Game"_sv, 0x8000009f},
	{"libSceNpTcs"_sv, 0x800000a0},
	{"libSceAbstractTcs"_sv, 0x800000a1},
	{"libSceBgsStorage"_sv, 0x800000a3},
	{"libSceWebmParserMdrw"_sv, 0x800000a4},
	{"libSceIdu"_sv, 0x800000a6},
	{"libSceAppDbShellCoreClient"_sv, 0x800000a7},
	{"libSceIcu"_sv, 0x800000a8},
	{"libSceGLSlimVSH"_sv, 0x800000a9},
	{"libicu"_sv, 0x800000aa},
	{"libpng16"_sv, 0x800000ab},
	{"libcairo"_sv, 0x800000ac},
	{"libSceContentListController"_sv, 0x800000ad},
	{"libSceJsc"_sv, 0x800000b0},
	{"libcurl"_sv, 0x800000b1},
	{"libSceVideoStreamingEngine_sys"_sv, 0x800000b2},
	{"libSceSystemLogger2"_sv, 0x800000b3},
	{"libSceJxr"_sv, 0x800000b4},
	{"libSceJxrParser"_sv, 0x800000b5},
	{"libSceMediaFrameworkUtil"_sv, 0x800000b6},
	{"libSceRemotePlayClientIpc"_sv, 0x800000b9},
}};

static_assert(SYSMODULES["libSceSystemService"_sv] != 0, "libSceSystemService not found");
static_assert(SYSMODULES["libDummy"_sv] == 0, "libDummy found?");
