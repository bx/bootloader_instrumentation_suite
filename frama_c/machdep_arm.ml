(* MIT License *)

(* Copyright (c) 2017 Rebecca ".bx" Shapiro *)

(* Permission is hereby granted, free of charge, to any person obtaining a copy *)
(* of this software and associated documentation files (the "Software"), to deal *)
(* in the Software without restriction, including without limitation the rights *)
(* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell *)
(* copies of the Software, and to permit persons to whom the Software is *)
(* furnished to do so, subject to the following conditions: *)

(* The above copyright notice and this permission notice shall be included in all *)
(* copies or substantial portions of the Software. *)

(* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR *)
(* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, *)
(* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE *)
(* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER *)
(* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, *)
(* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE *)
(* SOFTWARE. *)

(* Contents of e.g. file cil/src/machdep_x86_32.ml properly modified for your
     architecture. The MSVC configuration is never used by Frama-C, no need
     to edit it (but it must be included). *)
  
  open Cil_types

  let arm = {
      version          = "arm machdep";
      compiler         = "gcc";
    (* All types but char and long long are 16 bits *)
    sizeof_short     = 2;
    sizeof_int       = 4;
    sizeof_long      = 4;
    sizeof_longlong  = 8;
    sizeof_float     = 4;
    sizeof_double    = 8;
    sizeof_longdouble = 8;
    sizeof_ptr       = 4;
    sizeof_void      = 4; (* ? *)
    sizeof_fun       = 1;(* ? *)
    wchar_t = "int"; (* ? *)
    alignof_str = 1; (* ? *)
    alignof_fun = 1; (* ? *)
    char_is_unsigned = false; (* ? *)
    underscore_name = false; (* ? *)
    const_string_literals = false; (* ? *)
    alignof_aligned = 8;(* ? *)
    has__builtin_va_list = true;(* ? *)
    __thread_is_keyword = true; (* ? *)
    alignof_short    =  2;
    alignof_int      = 4;
    alignof_long     = 4;
    alignof_longlong = 8;
    alignof_float    = 4;
    alignof_double   = 8;
    alignof_longdouble = 8;
    alignof_ptr      = 4;
    little_endian = true;
    size_t = "unsigned int";
    ptrdiff_t = "int";
    
  }

let () = File.new_machdep "arm" arm
                          
