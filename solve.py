#Check function is functions having syslog or printf in its name (logging Procedures)
#Now finding lms string using backward traversal
#Also do Peephole concretization
import angr
import claripy
import pyvex
import string
import itertools

proj = angr.Project("apache2",load_options={'auto_load_libs':False})

def log_functions():
  check_func = set()
  cfg  = proj.analyses.CFGFast(resolve_indirect_jumps = True,data_references=True,cross_references=True)
  entry_func = cfg.kb.functions.items()
  for addr,func in entry_func:
    if 'print' in func.name:
      check_func.add(addr)
    if 'syslog' in func.name:
    	check_func.add(addr)
  return cfg,check_func

def extract_call_sites(cfg,check_func):
	req_func = set()
	for func in check_func:
		bb_addr =  cfg.kb.functions[func].block_addrs
		for addr in bb_addr:
			node = cfg.get_any_node(addr)
			predec = node.predecessors
			for predecessors in predec:
				req_func.add(predecessors.function_address)
	return req_func

def symbolic_execution(addr,cfg):
  req_strings = []
  try:
    entry_func = cfg.kb.functions[addr]
  except :
    print("do something about it")
  else:
    try:
      temp_string = entry_func.string_references(minimum_length=4,vex_only=True)
    except:
      print("")
    else:
      req_strings = temp_string
      return req_strings
    return []
  return []

def peephole(cfg,call_sites,max_back_trace):
  req_string = set()
  set_call = set()
  temp_call_sites = tuple(call_sites)
  set_call.add((temp_call_sites,0))
  while len(set_call) != 0:
    iter_list,back_trace = set_call.pop()
    for addr in iter_list:
      l = symbolic_execution(addr,cfg)
      if len(l)!=0:
        for strings in l:
          req_string.add(strings)
      elif back_trace < max_back_trace:
        node = cfg.get_any_node(addr)
        if node!=None:
          predecessors = node.predecessors
          if predecessors!=None and len(predecessors)!=0:
            predec = []
            for predecessor in predecessors:
              predec.append(predecessor.function_address)
            temp_predec = tuple(predec)
            set_call.add((temp_predec,back_trace+1))
  return req_string

# def hexescape(s):
#   '''
#   perform hex escaping on a raw string s
#   '''
#   out = []
#   acceptable = (string.ascii_letters + string.digits + " .%?").encode()
#   for c in s:
#       if c not in acceptable:
#           continue
#       else:
#           out.append(chr(c))

#   fnd_string = ''.join(out)
#   if(len(fnd_string)>2):
#     return fnd_string


# def random(cfg):
#   req_strings = set()
#   state = proj.factory.blank_state()
#   string_references = []
#   for v in cfg._memory_data.values():
#       if v.sort == "string" and v.size > 1:
#           st = state.solver.eval(state.memory.load(v.address, v.size), cast_to=bytes)
#           string_references.append((v.address, st))

#   strings = [] if len(string_references) == 0 else list(list(zip(*string_references))[1])

#   valid_strings = []
#   if len(strings) > 0:
#       for s in strings:
#           if len(s) <= 128:
#               valid_strings.append(s)
        
#   for s in set(valid_strings):
#       s_val = hexescape(s)
#       req_strings.add(s_val)
#   return req_strings



cfg,check_func = log_functions()
req_func = extract_call_sites(cfg,check_func)
req_strings = peephole(cfg,req_func,3)
print(req_strings)


