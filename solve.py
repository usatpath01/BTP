#Check function is functions having syslog or printf in its name (logging Procedures)
#Now finding lms string using backward traversal
#Also do Peephole concretization
#Taking too much time
#Ask TA how to tackle extracting strings
#Tommorrow morning
import angr
import claripy
import pyvex

proj = angr.Project("apache2",load_options={'auto_load_libs':False})

def log_functions():
  check_func = set()
  cfg  = proj.analyses.CFGFast()
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
				req_func.add(predecessors.addr)
	return req_func

def symbolic_execution(addr,cfg):
  req_strings = []
  try:
    entry_func = cfg.kb.functions[addr]
  except :
    print("do something about it")
  else:
    try:
      temp_string = entry_func.string_references()
    except:
      print("")
    else:
      req_strings = temp_string
      return req_strings
    return []
  return []

def check(cfg,address):
  req_string = set()
  try:
    state = proj.factory.entry_state(addr = address)
  except TypeError:
    print("")
  else:
  	try:
  		succ = state.step()
  	except:
  		print("")
  	else:
  		for st in succ.successors:
  			temp = st.posix.dumps(1)
  			if temp!=None and len(temp)>0:
  				req_string.add(temp)
  return req_string


def peephole(cfg,call_sites,max_back_trace):
  req_string = set()
  set_call = set()
  temp_call_sites = tuple(call_sites)
  set_call.add((temp_call_sites,0))
  while len(set_call) != 0:
    iter_list,back_trace = set_call.pop()
    for addr in iter_list:
      l = check(cfg,addr)
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
              predec.append(predecessor.addr)
            temp_predec = tuple(predec)
            set_call.add((temp_predec,back_trace+1))
  return req_string


cfg,check_func = log_functions()
req_func = extract_call_sites(cfg,check_func)
print(req_func)
req_strings = peephole(cfg,req_func,5)
print(req_strings)

