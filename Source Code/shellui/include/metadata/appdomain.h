/**
 * \file
 * AppDomain functions
 *
 * Author:
 *	Dietmar Maurer (dietmar@ximian.com)
 *
 * (C) 2001 Ximian, Inc.
 */

#ifndef _MONO_METADATA_APPDOMAIN_H_
#define _MONO_METADATA_APPDOMAIN_H_

#include <utils/mono-publib.h>

#include <utils/mono-forward.h>
#include <metadata/object.h>
#include <metadata/reflection.h>

MONO_BEGIN_DECLS

typedef void (*MonoThreadStartCB) (intptr_t tid, void* stack_start,
				   void* func);
typedef void (*MonoThreadAttachCB) (intptr_t tid, void* stack_start);

typedef struct _MonoAppDomain MonoAppDomain;

typedef void (*MonoDomainFunc) (MonoDomain *domain, void* user_data);

MONO_END_DECLS

#endif /* _MONO_METADATA_APPDOMAIN_H_ */

