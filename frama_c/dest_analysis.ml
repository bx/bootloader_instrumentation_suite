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

  let has_fulladdr info =
    not (Integer.is_zero info.lvalfulladdr)
        
  let get_fulladdr info =
    info.lvalfulladdr
      
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


let help_msg = "Resolves as many memory write destinations as possible"

module Self = Plugin.Register
                (struct
                  let name = "write destination resolver"
                  let shortname = "dst"
                  let help = help_msg
                end)

module Enabled = Self.False
                   (struct
                     let option_name = "-dst"
                     let help = "when on (off by default), " ^ help_msg
                   end)
module More_enabled = Self.False
                   (struct
                     let option_name = "-dst-more"
                     let help = "print more dst info, " ^ help_msg
                   end)

module Output_file = Self.String
                       (struct
                         let option_name = "-dst-output"
                         let default = "-"
                         let arg_name = "output_file"
                         let help =
                           "file where the message is output (default: console)"
                       end)

                       
module Location_helper= struct
  let loc_to_loc_and_size loc =
    (Locations.loc_to_loc_without_size loc, Locations.loc_size loc)
                                      
  let l_to_string pretty l =
    let s = pretty Format.str_formatter l in
    Format.flush_str_formatter s
                               
  let locbytes_to_string l =
    l_to_string Locations.Location_Bytes.pretty l
                
  let precise_to_string l =
    l_to_string Precise_locs.pretty_loc l

  let int_to_string i =
    l_to_string Abstract_interp.Int.pretty i

  let loc_bytes_to_addr_int l =
    try
      match l with
        (Locations.Location_Bytes.Map(m), _) -> (
        match Locations.Location_Bytes.M.find Base.null m with
          Ival.Set([|i|]) -> i
        (*| Ival.Set(s) -> ?? what to do when there is more than 1 solution *)
        | _ -> Integer.zero (* zero or more than one results *)
      )
      | _ -> Integer.zero (* no location map *)
    with Not_found -> Integer.zero    

  let get_min_max l =
    try (* value/eval_typ.ml... sizeof_lval_typ typlv *)
      (match l with
         (llv, lsz) ->
         (match ((Cvalue.V.project_ival llv), (Int_Base.project lsz)) with
            (v, sz) ->
            (match Ival.min_and_max v with
               (Some(min), Some(max)) -> (Some(min), Some(Integer.add max (Integer.native_div sz (Integer.of_int 8))))
             | _ -> (None, None))))
    with Cvalue.V.Not_based_on_null -> (None, None)
               
      
      (* Cvalue.V.project_ival : V.t -> Ival.t *)
end


module Instr_info = struct
  type instrinfo = {
      lval:Cil_types.lval;
      exp:Cil_types.exp;
      lexloc:Cil_types.location;
      lvalloc:Locations.location;
      lvalfulladdr:Integer.t;
      instr:Cil_types.instr;
      min:Abstract_interp.Int.t option;
      max:Abstract_interp.Int.t option;
      callinfo:SS.t;
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

  let has_fulladdr info =
    not (Integer.is_zero info.lvalfulladdr)
        
  let get_fulladdr info =
    info.lvalfulladdr

  let callstack_str info =
    if SS.is_empty info.callinfo then
      ""
    else
      SS.choose info.callinfo
      
  let lval_string info =
    let s = Printer.pp_lval Format.str_formatter info.lval in
    Format.flush_str_formatter s
              
  let build_instrinfo st kinstr =
    if Db.Value.is_computed() then
      match st.skind with
        Instr (Set(lv, e, location) as s) ->  (let lvl = eval_lval lv kinstr in
                                               (let (min, max) = Location_helper.get_min_max (Location_helper.loc_to_loc_and_size lvl) in
                                                 (let  ii = {
                                                      lval = lv;
                                                      exp = e;
                                                      lexloc = location;
                                                      lvalloc = lvl;
                                                      lvalfulladdr = Location_helper.loc_bytes_to_addr_int (Location_helper.loc_to_loc_and_size lvl);
                                                      instr = s;
                                                      min = min;
                                                      max = max;
						      callinfo = Funcall_info.build_callinfo st kinstr;
                                                    }
                                                  in Some(ii)
                                                 )
                                               )
                                              )
      | _ -> None
    else
      None
end
                          
let print_msg =
  object (self : 'self)
    val mutable tofile = if Output_file.is_default() then false else true
    val mutable file_chan = if Output_file.is_default() then stdout else open_out (Output_file.get())

    method ival_string ival =
        (let s = Abstract_interp.Int.pretty Format.str_formatter ival in
         Format.flush_str_formatter s;
        )

    method print_range info =
      (let {Instr_info.min=min; Instr_info.max=max; _} = info in
       match (min, max) with
         Some(min'), Some(max') ->
         self#print (Printf.sprintf "[%s, %s] %s in %s .. %s\n" (self#ival_string min') (self#ival_string max') (Instr_info.lval_string info) (Instr_info.lexloc_string info) (Instr_info.callstack_str info));
       | _ -> ();
      )
    method print_more info enabled =
      if enabled then 
        (let s = Locations.pretty Format.str_formatter (Instr_info.get_lvalloc info) in
         self#print (Printf.sprintf "%s = %s (%s) .. %s \n" (Instr_info.instr_string info) (Format.flush_str_formatter s) (Instr_info.lexloc_string info) (Instr_info.callstack_str info));
        );
      ()

    method print_nonzero_lvalue_addr info =
      if Instr_info.has_fulladdr info then
        self#print (Printf.sprintf "(%s) %s in %s .. %s\n" (Location_helper.int_to_string (Instr_info.get_fulladdr info)) (Instr_info.lval_string info) (Instr_info.lexloc_string info) (Instr_info.callstack_str info));
      ()
        
    method print msg =
      if tofile then
        Printf.fprintf file_chan "%s\n" msg
      else
        Self.result "%s" msg                      
    method close =
      if tofile then
        close_out file_chan
  end
                              
class print_dsts print_obj more = object (self: 'self)
    
  inherit Visitor.frama_c_inplace

  method! vstmt_aux s =
    (match Instr_info.build_instrinfo s self#current_kinstr with
       Some(info) -> ((* print_obj#print_nonzero_lvalue_addr info;*) print_obj#print_range info;
                     print_obj#print_more info more)
     | _ -> ()
    );
    Cil.DoChildren
end


                                  
let run () =
  if Enabled.get() then
    Visitor.visitFramacFileSameGlobals ( new print_dsts print_msg (More_enabled.get())) (Ast.get ());
  print_msg#close
  
    
               
let () = Db.Main.extend run
                         
