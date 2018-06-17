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

open Cil_types
open Cil
open Printf
open Cil_types
open Cil
  
module SS = Set.Make(String)
module Funcall_info = struct                      
  type funcallinfo = {
      lval:Cil_types.lval;
      exp:Cil_types.exp;
      lexloc:Cil_types.location;
      lvalloc:Locations.location;
      lvalfulladdr:Integer.t;
      instr:Cil_types.instr;
      min:Abstract_interp.Int.t option;
      max:Abstract_interp.Int.t option;
    }
                     
  let is_instr s =
    match s with
      Instr _ -> true
    | _ -> false

  let lexloc_string info =
    let ({Lexing.pos_fname=f1; Lexing.pos_lnum=l1; _}, _) = info.lexloc in
    Printf.sprintf "%s:%d"  f1 l1 

  let get_lval info =
    info.lval

  let get_lvalloc info =
    info.lvalloc

    
  let instr_string info =
    let s = Printer.pp_instr Format.str_formatter info.instr in
    Format.flush_str_formatter s
      
  let eval_lval lval kinstr =
    !Db.Value.lval_to_loc ~with_alarms:CilE.warn_none_mode kinstr lval

  let lval_string info =
    let s = Printer.pp_lval Format.str_formatter info.lval in
    Format.flush_str_formatter s

  let form_callstack_string cs =
    List.fold_right (fun c s -> (match c with (f, _) ->
                                   s ^ "->" ^ (Ast_info.Function.get_name f.fundec))) cs ""
             
  let build_callinfo s kinstr =
    if (Db.Value.is_computed()) && (Db.Value.is_reachable_stmt s)  then
      (match Db.Value.get_stmt_state_callstack ~after:true s with
         None -> SS.empty
       | Some(state) -> Value_types.Callstack.Hashtbl.fold
                          (fun cs state r ->
                            (if Cvalue.Model.is_reachable state then
                               SS.add (form_callstack_string cs) r
                             else
                               SS.empty))
                              state SS.empty)
    else
      SS.empty
end

  
let help_msg = "static function call stack analyzer"

module Self = Plugin.Register
                (struct
                  let name = "static function call stack analyzer"
                  let shortname = "call"
                  let help = help_msg
                end)

module Enabled = Self.False
                   (struct
                     let option_name = "-call"
                     let help = "when on (off by default), " ^ help_msg
                   end)

module Output_file = Self.String
                       (struct
                         let option_name = "-call-output"
                         let default = "-"
                         let arg_name = "output_file"
                         let help =
                           "file where the message is output (default: console)"
                       end)
                    
let print_msg =
  object (self : 'self)
    method print msg stream =
      (match stream with
        Some(s) -> Printf.fprintf s "%s\n" msg; Self.result "%s" msg
      | None -> Self.result "%s" msg)
      
    method close stream =
      (match stream with
         Some(s) -> close_out s
       | None -> ())

 end

class call_visitor kf =
object (self)
  inherit Visitor.frama_c_inplace
        
  val mutable callstacks = SS.empty
  method! vstmt stmt =  callstacks <- SS.union (Funcall_info.build_callinfo stmt self#current_kinstr) callstacks;
                        Cil.DoChildren;
  method result = callstacks                              
end
  
let run_call () =
  if Enabled.get() then
    let stream =
      if (Output_file.is_default()) then
        None
      else
        Some (open_out (Output_file.get()))
    in
    Globals.Functions.iter (fun name ->
        (try let d = (Kernel_function.get_definition name) in
             (let calls = new call_visitor name in
              ignore (Visitor.visitFramacFunction (calls :> Visitor.frama_c_visitor) d);
              let res = calls#result in SS.iter (fun s -> print_msg#print (String.sub s 2 ((String.length s) - 2 )) stream) res)
         with _ -> ()));
    print_msg#close stream
  
                                       
               
let () = Db.Main.extend run_call                          
