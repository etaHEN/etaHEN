/**
 * \file
 */

#ifndef _MONO_CLI_CLASS_H_
#define _MONO_CLI_CLASS_H_

#include <metadata/metadata.h>
#include <metadata/image.h>
#include <metadata/loader.h>
#include <utils/mono-error.h>

MONO_BEGIN_DECLS

typedef struct MonoVTable MonoVTable;

typedef struct _MonoClassField MonoClassField;
typedef struct _MonoProperty MonoProperty;
typedef struct _MonoEvent MonoEvent;

MONO_END_DECLS

#endif /* _MONO_CLI_CLASS_H_ */
