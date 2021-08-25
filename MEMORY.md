# Memory Model

This document provides an overview of the memory model of libCwtch. Callers should consult this document to ensure
that they are properly handling pointers passed to-and-from libCwtch.

## Pointer Parameters

All pointers **passed** into functions in this library, except `c_FreePointer`, are assumed to be owned by the caller. 

libCwtch **will not** modifying the underlying memory, nor attempt to free or otherwise modify these pointers.

This is realized by copying the underlying memory using `C.GoStringN`. libCwtch guarantees that it will not depend
on the underlying memory of these pointers being available after returning from this function.

Callers are responsible for freeing these pointers after the call has been completed. 

## Returned Pointers

All pointers **returned** by functions in libCwtch should be assumed to owned by libCwtch 

Callers **must not** modifying the underlying memory of these pointers, nor attempt to free or otherwise modify these pointers
through any method other than the one provided below.

Calling functions **must** copy the contents of the memory into their own memory space and then call `c_FreePointer` providing
the returned pointer as a parameter.

libCwtch guarantees that it will not modify or free the underlying memory of these pointers prior to a call to `c_FreePointer`.