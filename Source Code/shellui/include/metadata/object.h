/**
 * \file
 */

#ifndef _MONO_CLI_OBJECT_H_
#define _MONO_CLI_OBJECT_H_

#include <utils/mono-forward.h>
#include <metadata/object-forward.h>
#include <metadata/class.h>
#include <utils/mono-error.h>

MONO_BEGIN_DECLS

typedef mono_byte MonoBoolean;

typedef struct _MonoString MONO_RT_MANAGED_ATTR MonoString;
typedef struct _MonoArray MONO_RT_MANAGED_ATTR MonoArray;
typedef struct _MonoReflectionMethod MONO_RT_MANAGED_ATTR MonoReflectionMethod;
typedef struct _MonoReflectionModule MONO_RT_MANAGED_ATTR MonoReflectionModule;
typedef struct _MonoReflectionField MONO_RT_MANAGED_ATTR MonoReflectionField;
typedef struct _MonoReflectionProperty MONO_RT_MANAGED_ATTR MonoReflectionProperty;
typedef struct _MonoReflectionEvent MONO_RT_MANAGED_ATTR MonoReflectionEvent;
typedef struct _MonoReflectionType MONO_RT_MANAGED_ATTR MonoReflectionType;
typedef struct _MonoDelegate MONO_RT_MANAGED_ATTR MonoDelegate;
typedef struct _MonoThreadsSync MonoThreadsSync;
typedef struct _MonoThread MONO_RT_MANAGED_ATTR MonoThread;
typedef struct _MonoDynamicAssembly MonoDynamicAssembly;
typedef struct _MonoDynamicImage MonoDynamicImage;
typedef struct _MonoReflectionMethodBody MONO_RT_MANAGED_ATTR MonoReflectionMethodBody;
typedef struct _MonoAppContext MONO_RT_MANAGED_ATTR MonoAppContext;

struct _MonoObject {
	MonoVTable *vtable;
	MonoThreadsSync *synchronisation;
};

typedef MonoObject* (*MonoInvokeFunc)	     (MonoMethod *method, void *obj, void **params, MonoObject **exc, MonoError *error);
typedef void*    (*MonoCompileFunc)	     (MonoMethod *method);
typedef void	    (*MonoMainThreadFunc)    (void* user_data);

#define MONO_OBJECT_SETREF(obj,fieldname,value) do {	\
		mono_gc_wbarrier_set_field ((MonoObject*)(obj), &((obj)->fieldname), (MonoObject*)value);	\
		/*(obj)->fieldname = (value);*/	\
	} while (0)

/* This should be used if 's' can reside on the heap */
#define MONO_STRUCT_SETREF(s,field,value) do { \
        mono_gc_wbarrier_generic_store (&((s)->field), (MonoObject*)(value)); \
    } while (0)

#define mono_array_addr(array,type,index) ((type*)mono_array_addr_with_size ((array), sizeof (type), (index)))
#define mono_array_get(array,type,index) ( *(type*)mono_array_addr ((array), type, (index)) ) 
#define mono_array_set(array,type,index,value)	\
	do {	\
		type *__p = (type *) mono_array_addr ((array), type, (index));	\
		*__p = (value);	\
	} while (0)
#define mono_array_setref(array,index,value)	\
	do {	\
		void **__p = (void **) mono_array_addr ((array), void*, (index));	\
		mono_gc_wbarrier_set_arrayref ((array), __p, (MonoObject*)(value));	\
		/* *__p = (value);*/	\
	} while (0)
#define mono_array_memcpy_refs(dest,destidx,src,srcidx,count)	\
	do {	\
		void **__p = (void **) mono_array_addr ((dest), void*, (destidx));	\
		void **__s = mono_array_addr ((src), void*, (srcidx));	\
		mono_gc_wbarrier_arrayref_copy (__p, __s, (count));	\
	} while (0)

MONO_END_DECLS

#endif

