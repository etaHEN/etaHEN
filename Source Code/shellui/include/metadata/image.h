/**
 * \file
 */

#ifndef _MONONET_METADATA_IMAGE_H_ 
#define _MONONET_METADATA_IMAGE_H_

#include <stdio.h>
#include <utils/mono-publib.h>
#include <utils/mono-error.h>
#include <metadata/object-forward.h>

MONO_BEGIN_DECLS

typedef struct _MonoAssembly MonoAssembly;
typedef struct _MonoAssemblyName MonoAssemblyName;
typedef struct _MonoTableInfo MonoTableInfo;

typedef enum {
	MONO_IMAGE_OK,
	MONO_IMAGE_ERROR_ERRNO,
	MONO_IMAGE_MISSING_ASSEMBLYREF,
	MONO_IMAGE_IMAGE_INVALID
} MonoImageOpenStatus;

MONO_END_DECLS

#endif
