#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
	const char *name;
	const size_t length;
	const uint32_t hash;
	const uint32_t id;
} Sysmodule;

typedef struct {
	// this isn't in Sysmodule to save space
	const char *restrict name;
	const size_t length;
	const uint32_t hash;
} HashedString;

#define STRING_VIEW(str) str, (sizeof(str) - 1)

// pre-sorted array of sysmodules
const Sysmodule SYSMODULES[] = {
	{STRING_VIEW("libSceNetCtl"), 0x7cd526ae, 0x80000009},
	{STRING_VIEW("libSceRemotePlayClientIpc"), 0x7f336b67, 0x800000b9},
	{STRING_VIEW("libSceNpManager"), 0x83137e1b, 0x8000000d},
	{STRING_VIEW("libSceRegMgr"), 0x83a2c454, 0x8000001f},
	{STRING_VIEW("libSceLibreSsl"), 0x83d4bae4, 0x80000065},
	{STRING_VIEW("libSceKbEmulate"), 0x85a59a2c, 0x80000031},
	{STRING_VIEW("libSceAudioIn"), 0x889bee2b, 0x80000002},
	{STRING_VIEW("libSceSocialScreen"), 0x88a071a9, 0x800000ae},
	{STRING_VIEW("libSceVcodec"), 0x8a5df0d0, 0x80000091},
	{STRING_VIEW("libSceAudioOut"), 0x8ae1ef08, 0x80000001},
	{STRING_VIEW("libSceSystemLogger2Game"), 0x8ec7a095, 0x8000009f},
	{STRING_VIEW("libSceNpCommon"), 0x90d635bd, 0x8000000c},
	{STRING_VIEW("libSceImageUtil"), 0x91cf6a8d, 0x80000059},
	{STRING_VIEW("libSceOpusSilkEnc"), 0x933eaf96, 0x80000068},
	{STRING_VIEW("libSceVideoOut"), 0x95577843, 0x80000022},
	{STRING_VIEW("libSceDataTransfer"), 0x96e87525, 0x80000057},
	{STRING_VIEW("libSceVdecSvp9.native"), 0x981d33fd, 0x800000af},
	{STRING_VIEW("libSceDipsw"), 0x9820e6bf, 0x80000029},
	{STRING_VIEW("libSceHttp2"), 0x985e533a, 0x8000008c},
	{STRING_VIEW("libSceNKWeb"), 0x989fcf07, 0x80000079},
	{STRING_VIEW("libSceNpSns"), 0x98b092e6, 0x8000001b},
	{STRING_VIEW("libSceNpTcs"), 0x98b09552, 0x800000a0},
	{STRING_VIEW("libSceResourceArbitrator"), 0x98cb052a, 0x80000092},
	{STRING_VIEW("libSceWebmParserMdrw"), 0x99d8c2c4, 0x800000a4},
	{STRING_VIEW("libSceNpWebApi2"), 0x9a2dad3a, 0x8000008f},
	{STRING_VIEW("libSceAudiodecCpuLpcm"), 0x9bad373a, 0x8000002e},
	{STRING_VIEW("libSceAudiodecCpuTrhd"), 0x9bb0e246, 0x80000082},
	{STRING_VIEW("libSceVdecCore.native"), 0x9f0c846a, 0x80000015},
	{STRING_VIEW("libSceVideoStreamingEngine_sys"), 0xa1819847, 0x800000b2},
	{STRING_VIEW("libSceAudiodecCpuDtsHdMa"), 0xa2c17667, 0x8000002d},
	{STRING_VIEW("libSceGifParser"), 0xaad65793, 0x8000005e},
	{STRING_VIEW("libSceAbstractTcs"), 0xabd0eaf2, 0x800000a1},
	{STRING_VIEW("libSceMetadataReaderWriter"), 0xacd7cf55, 0x8000005a},
	{STRING_VIEW("libSceAgcDriver"), 0xaf380e15, 0x80000080},
	{STRING_VIEW("libSceTEEClient"), 0xaf5fbf8f, 0x800000a2},
	{STRING_VIEW("libSceAvSetting"), 0xaf76e6eb, 0x80000021},
	{STRING_VIEW("libSceGvMp4Parser"), 0xb05b64d1, 0x8000005c},
	{STRING_VIEW("libSceEmbeddedTts"), 0xb06ac999, 0x8000009c},
	{STRING_VIEW("libSceNpWebApi"), 0xb26491f8, 0x8000000e},
	{STRING_VIEW("libSceWebKit2Secure"), 0xb68347b7, 0x80000074},
	{STRING_VIEW("libSceVdecSavc2.native"), 0xbcd7752a, 0x80000036},
	{STRING_VIEW("libicu"), 0xbe4129f6, 0x800000aa},
	{STRING_VIEW("libSceBackupRestoreUtil"), 0xbe8b971e, 0x8000003f},
	{STRING_VIEW("libSceVnaInternal"), 0xc3515916, 0x8000007c},
	{STRING_VIEW("libSceBgsStorage"), 0xc75fc93d, 0x800000a3},
	{STRING_VIEW("libSceOrbisCompat"), 0xc80ca3bb, 0x80000071},
	{STRING_VIEW("libSceHttpCache"), 0xcf4b4e6a, 0x80000078},
	{STRING_VIEW("libSceNpRemotePlaySessionSignaling"), 0xd06e11d0, 0x8000009a},
	{STRING_VIEW("libSceSaveData"), 0xd5260a37, 0x8000000f},
	{STRING_VIEW("libSceJpegParser"), 0xd58bea17, 0x8000005b},
	{STRING_VIEW("libSceShareInternal.native"), 0xe2aba1f9, 0x8000008e},
	{STRING_VIEW("libSceCommonDialog"), 0xe8476a83, 0x80000018},
	{STRING_VIEW("libSceCompositeExt"), 0xed53718a, 0x8000008b},
	{STRING_VIEW("libScePosixForWebKit"), 0xf0460938, 0x80000098},
	{STRING_VIEW("libSceFsInternalForVsh"), 0xf0d3fe7c, 0x80000066},
	{STRING_VIEW("libSceSulphaDrv"), 0xf0f458d9, 0x8000003b},
	{STRING_VIEW("libSceAudioSystem"), 0xf1346035, 0x80000083},
	{STRING_VIEW("libSceJemspace"), 0xf3520d24, 0x8000009e},
	{STRING_VIEW("libSceAppDbShellCoreClient"), 0xf57b298b, 0x800000a7},
	{STRING_VIEW("libSceLibreSsl3"), 0xf6c2a1cf, 0x800000b8},
	{STRING_VIEW("libSceJxrParser"), 0xf8a00cb3, 0x800000b5},
	{STRING_VIEW("libSceNpGameIntent"), 0xf8af0400, 0x8000008d},
	{STRING_VIEW("libSceWebKit2"), 0xf8ed9820, 0x80000073},
	{STRING_VIEW("libSceRazorCpu_debug"), 0xf9b744be, 0x80000075},
	{STRING_VIEW("libSceAbstractLocal"), 0xfad67ef9, 0x8000005f},
	{STRING_VIEW("libSceAgc"), 0xfba1278d, 0x80000094},
	{STRING_VIEW("libSceDbg"), 0xfba13239, 0x80000025},
	{STRING_VIEW("libSceIcu"), 0xfba1452b, 0x800000a8},
	{STRING_VIEW("libSceIdu"), 0xfba1454a, 0x800000a6},
	{STRING_VIEW("libSceJsc"), 0xfba14aca, 0x800000b0},
	{STRING_VIEW("libSceJxr"), 0xfba14b74, 0x800000b4},
	{STRING_VIEW("libSceMat"), 0xfba153f0, 0x80000048},
	{STRING_VIEW("libSceNet"), 0xfba1582d, 0x8000001c},
	{STRING_VIEW("libScePad"), 0xfba15f23, 0x80000024},
	{STRING_VIEW("libScePsm"), 0xfba1615a, 0x80000030},
	{STRING_VIEW("libSceRtc"), 0xfba168f1, 0x80000020},
	{STRING_VIEW("libSceSsl"), 0xfba16c9c, 0x8000000b},
	{STRING_VIEW("libSceWeb"), 0xfba179e4, 0x80000072},
	{STRING_VIEW("libSceSystemLogger2"), 0x589a03, 0x800000b3},
	{STRING_VIEW("libSceAgcResourceRegistration"), 0x32b6f14, 0x80000093},
	{STRING_VIEW("libSceSystemTts"), 0x97377d4, 0x80000097},
	{STRING_VIEW("libcurl"), 0x9e19e31, 0x800000b1},
	{STRING_VIEW("libSceNKWebKit"), 0xd1e264f, 0x8000007a},
	{STRING_VIEW("libSceGpuTrace"), 0xd85e769, 0x8000007b},
	{STRING_VIEW("libSceContentListController"), 0x11bca643, 0x800000ad},
	{STRING_VIEW("libSceEmbeddedTtsCoreG3"), 0x13afaba4, 0x8000009b},
	{STRING_VIEW("libSceAbstractStorage"), 0x1ab73689, 0x80000058},
	{STRING_VIEW("libScePngParser"), 0x1d8a5a38, 0x8000005d},
	{STRING_VIEW("libSceMediaFrameworkUtil"), 0x1f70390c, 0x800000b6},
	{STRING_VIEW("libSceVideoOutSecondary"), 0x1f7eb471, 0x80000046},
	{STRING_VIEW("libSceVisionManager"), 0x218f5135, 0x80000012},
	{STRING_VIEW("libSceAppInstUtil"), 0x24358339, 0x80000014},
	{STRING_VIEW("libSceGpuCapture"), 0x2438c46a, 0x8000007f},
	{STRING_VIEW("libSceRnpsAppMgr"), 0x27ff81c6, 0x80000076},
	{STRING_VIEW("libSceGLSlimVSH"), 0x297394d9, 0x800000a9},
	{STRING_VIEW("libSceAsyncStorageInternal"), 0x30d3f3ac, 0x80000077},
	{STRING_VIEW("libcairo"), 0x3248efe3, 0x800000ac},
	{STRING_VIEW("libpng16"), 0x3305faa9, 0x800000ab},
	{STRING_VIEW("libSceJitBridge"), 0x3542498e, 0x8000006f},
	{STRING_VIEW("libSceVoiceCommand"), 0x36caed29, 0x80000099},
	{STRING_VIEW("libSceUserService"), 0x3ad5c6fa, 0x80000011},
	{STRING_VIEW("libSceHidControl"), 0x3c76cfca, 0x80000017},
	{STRING_VIEW("libSceMediaFrameworkInterface"), 0x3d323a6f, 0x80000095},
	{STRING_VIEW("libSceSystemLogger2NativeQueueClient"), 0x3d6de7e2, 0x80000088},
	{STRING_VIEW("libSceOpusCeltDec"), 0x3e0bab89, 0x80000044},
	{STRING_VIEW("libSceOpusCeltEnc"), 0x3e0bb061, 0x80000043},
	{STRING_VIEW("libSceAgcVshDebug"), 0x3fb2a275, 0x80000087},
	{STRING_VIEW("libSceSystemLogger2Delivery"), 0x44db6717, 0x80000089},
	{STRING_VIEW("libSceSysCore"), 0x48619a9c, 0x80000004},
	{STRING_VIEW("libSceSysUtil"), 0x4869daff, 0x80000026},
	{STRING_VIEW("libSceLoginMgrServer"), 0x49a6dd82, 0x80000045},
	{STRING_VIEW("libSceAbstractYoutube"), 0x4fea1f31, 0x80000061},
	{STRING_VIEW("libSceAbstractTwitter"), 0x54689e81, 0x80000062},
	{STRING_VIEW("libSceSystemService"), 0x6235a416, 0x80000010},
	{STRING_VIEW("libSceCdlgUtilServer"), 0x63862811, 0x80000007},
	{STRING_VIEW("libSceOpusDec"), 0x659e6dd3, 0x80000069},
	{STRING_VIEW("libSceAc3Enc"), 0x666c7239, 0x80000013},
	{STRING_VIEW("libSceAgcVsh"), 0x66bae27e, 0x80000086},
	{STRING_VIEW("libSceAvcap2"), 0x678e6bc5, 0x80000085},
	{STRING_VIEW("libSceCamera"), 0x69d4ca95, 0x8000001a},
	{STRING_VIEW("libSceDseehx"), 0x6c83a62f, 0x80000056},
	{STRING_VIEW("libSceDtsEnc"), 0x6c97a367, 0x80000028},
	{STRING_VIEW("libSceAppChecker"), 0x6e6945c4, 0x80000032},
	{STRING_VIEW("libSceAjm.native"), 0x7054b351, 0x80000023},
	{STRING_VIEW("libSceJscCompiler"), 0x70d53189, 0x80000070},
	{STRING_VIEW("libSceComposite"), 0x72b7f517, 0x8000008a},
	{STRING_VIEW("libSceAjmi"), 0x7883d6f5, 0x8000007e},
	{STRING_VIEW("libSceAmpr"), 0x7883e29e, 0x800000b7},
	{STRING_VIEW("libSceBgft"), 0x78843f43, 0x8000002a},
	{STRING_VIEW("libSceHttp"), 0x78872bf8, 0x8000000a},
	{STRING_VIEW("libSceIpmi"), 0x78879073, 0x8000001d},
	{STRING_VIEW("libSceMbus"), 0x78892e63, 0x8000001e},
	{STRING_VIEW("libSceNgs2"), 0x7889b508, 0x80000090},
	{STRING_VIEW("libSceVenc"), 0x788d5014, 0x80000084},
	{STRING_VIEW("libSceVdecShevc.native"), 0x7965a924, 0x8000003c},
	{STRING_VIEW("libSceMarlin"), 0x7ae79fe3, 0x80000027},
	{STRING_VIEW("libSceVnaWebsocket"), 0x7b31d48e, 0x8000007d}
};

#define NUM_SYSMODULES (sizeof(SYSMODULES) / sizeof(Sysmodule))

static uint32_t hash_string(const char *restrict str, const size_t length) {
	uint32_t hash = 0;
	for (size_t i = 0; i < length; i++) {
		hash = 31 * hash + (str[i] & 0xff); // NOLINT(*)
	}
	return hash;
}

static int_fast32_t compare_entry(const Sysmodule *restrict entry, const HashedString *restrict key) {
	const int32_t value = (int32_t)(entry->hash - key->hash);
	const size_t length = entry->length <= key->length ? entry->length : key->length;
	return value != 0 ? value : memcmp(entry->name, key->name, length);
}

static int_fast32_t get_sysmodule_index(const char *restrict name, const size_t length) {
	const HashedString key = {
		.name = name,
		.length = length,
		hash_string(name, length)
	};
	int_fast32_t lo = 0;
	int_fast32_t hi = NUM_SYSMODULES - 1;

	while (lo <= hi) {
		const int_fast32_t m = (lo + hi) >> 1;
		const int_fast32_t n = compare_entry(SYSMODULES + m, &key);

		if (n == 0) {
			return m;
		}

		if (n < 0) {
			lo = m + 1;
		} else {
			hi = m - 1;
		}
	}
	return -(lo + 1);
}

uint32_t get_sysmodule_id(const char *restrict name, const size_t length) {
	const int_fast32_t index = get_sysmodule_index(name, length);
	return index >= 0 ? SYSMODULES[index].id : 0;
}
