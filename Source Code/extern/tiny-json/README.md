# tiny-json

[![Build Status](https://travis-ci.org/rafagafe/tiny-json.svg?branch=master)](https://travis-ci.org/rafagafe/tiny-json) [![GitHub contributors](https://img.shields.io/github/contributors/rafagafe/tiny-json.svg)](https://github.com/rafagafe/tiny-json/graphs/contributors)

tiny-json is a versatile and easy to use json parser written in C and suitable for embedded systems. It is fast, robust and portable.

It is not only a tokenizer. You can access json data in string format or get primitive values directly as C type variables without any loss of performance.

You can access the JSON fields one on one or get their values by their names. This helps you to save a lot of source code lines and development time.

* It does not use recursivity.
* It does not use dynamic memory. The memory you use can be reserved statically.
* There is no limit for nested levels in arrays or json objects.
* The JSON property number limit is determined by the size of a buffer that can be statically reserved.

If you need to create JSON strings please visit: https://github.com/rafagafe/json-maker

# Philosophy

When parsing a JSON text string a tree is created by linking json_t structures. Navigating or querying this tree is very easy using the provided API.

To maintain reduced memory usage and fast processing the strings are not copied. When you request the value of a JSON element, a reference to the original JSON string is returned.

To facilitate the processing of the data the returned strings are null-terminated. This is achieved by setting the null character to JSON control characters such as commas, brackets, braces, and quotation marks.

# API
The tiny-json API provides two types. `jsonType_t` is an enumeration for all possible JSON field types. `json_t` is a structure containing internal data which you don't need to know.
```C
typedef enum {
    JSON_OBJ, JSON_ARRAY, JSON_TEXT, JSON_BOOLEAN,
    JSON_INTEGER, JSON_REAL, JSON_NULL
} jsonType_t;
```
To parse a JSON string use `json_create()`. We pass it an array of `json_t` for it to allocate JSON fields.
If the JSON string is bad formated or has more fields than the array this function returns a null pointer.
```C
enum { MAX_FIELDS = 4 };
json_t pool[ MAX_FIELDS ];

char str[] = "{ \"name\": \"peter\", \"age\": 32 }";	

json_t const* parent = json_create( str, pool, MAX_FIELDS );
if ( parent == NULL ) return EXIT_FAILURE;
```
To get a field by its name we use `json_getProperty()`. If the field does not exist the function returns a null pointer.
To get the type of a field we use `json_getType()`.
```C
json_t const* namefield = json_getProperty( parent, "name" );
if ( namefield == NULL ) return EXIT_FAILURE;
if ( json_getType( namefield ) != JSON_TEXT ) return EXIT_FAILURE;
```
To get the value of a field in string format we use `json_getValue()`. It always returns a valid null-teminated string.
```C
char const* namevalue = json_getValue( namefield );
printf( "%s%s%s", "Name: '", namevalue, "'.\n" );
```
For primitive fields we can use a specific function to get the fields value directly as a C type, f.i. `json_getInteger()` or we can use `json_getValue()` to get its value in text format.
```C
json_t const* agefield = json_getProperty( parent, "age" );
if ( agefield == NULL ) return EXIT_FAILURE;
if ( json_getType( agefield ) != JSON_INTEGER ) return EXIT_FAILURE;

int64_t agevalue = json_getInteger( agefield );
printf( "%s%lld%s", "Age: '", agevalue, "'.\n" );

char const* agetxt = json_getValue( agefield );
printf( "%s%s%s", "Age: '", agetxt, "'.\n" );
```
For an example how to use nested JSON objects and arrays please see example-01.c.
