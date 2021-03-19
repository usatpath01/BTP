#Check function is functions having syslog or printf in its name (logging Procedures)
#Now finding lms string using backward traversal
#Also do Peephole concretization
#improve get_predecessor_string now in O((n+m)^2) have to do in O((n+m))
import angr
import claripy
import pickle
import pyvex
import string
import itertools
import networkx as nx
import matplotlib.pyplot as plt
from angrutils import *

proj = angr.Project("skod",load_options={'auto_load_libs':False})

def log_functions():
  check_func = set()
  not_check_func = set()
  cfg  = proj.analyses.CFGFast(normalize = True,resolve_indirect_jumps = True,data_references=True,cross_references=True)
  entry_func = cfg.kb.functions.items()
  for addr,func in entry_func:
    if 'print' in func.name:
      check_func.add(addr)
    if 'syslog' in func.name:
    	check_func.add(addr)
    else:
      not_check_func.add(addr)
  return cfg,check_func,not_check_func

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
    print("")
  else:
    try:
      temp_string = entry_func.string_references(minimum_length=4,vex_only=True)
    except:
      print("")
    else:
      for addr,string in temp_string:
        req_strings.append(string)
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

def hexescape(s):
  '''
  perform hex escaping on a raw string s
  '''
  out = []
  acceptable = (string.ascii_letters + string.digits + " .%?").encode()
  for c in s:
      if c not in acceptable:
          continue
      else:
          out.append(chr(c))

  fnd_string = ''.join(out)
  if(len(fnd_string)>2):
    return fnd_string


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

# def build_lms_paths(cfg,lms_strings,cfg_functions):
#   paths = set()
#   for function in cfg_functions:
#     temp = get_local_paths(cfg,function,lms_strings)

def get_local_paths(cfg,function,lms_strings):
  entry_func = cfg.kb.functions[function]
  local_grp = entry_func._local_transition_graph
  print(local_grp)

st = proj.factory.entry_state()
# def testing_purposes(addr,cfg):
#   entry_func = cfg.kb.functions[addr]
#   bbs = entry_func.blocks
#   for bb_addr in bbs:
#     try:
#       ins_addr = bb_addr.instruction_addrs
#     except:
#       continue
#     else:
#       starting = min(ins_addr)
#       ending = max(ins_addr)
#       references = cfg.kb.xrefs
#       temp = references.get_xrefs_by_ins_addr_region(starting, ending)
#       tmp = list(temp)
#       for temptmp in tmp:
#         try:
#           t = temptmp.memory_data
#         except TypeError:
#           continue
#         else:
#           if t!=None: 
#             if t.sort!=None and 'string' in t.sort and t.size>1:
#               req_addr = t.address
#               yeah = st.memory.load(req_addr,t.size-1)
#               print(st.solver.eval(yeah,cast_to=bytes))


def testing_purposes2(node,cfg):
  try:
    ins_addr = node.instruction_addrs
  except:
    return ''
  else:
    if(len(ins_addr)>0):
      starting = min(ins_addr)
      ending = max(ins_addr)
      references = cfg.kb.xrefs
      temp = references.get_xrefs_by_ins_addr_region(starting, ending)
      tmp = list(temp)
      for temptmp in tmp:
        try:
          t = temptmp.memory_data
        except TypeError:
          continue
        else:
          if t!=None: 
            if t.sort!=None and 'string' in t.sort and t.size>1:
              req_addr = t.address
              yeah = st.memory.load(req_addr,t.size-1)
              temp_string = st.solver.eval(yeah,cast_to=bytes).decode("utf-8")
              if temp_string in req_strings:
                return temp_string

  return ''

visited = set()
queue = []
req_graph = {}

def get_predecessor_string(cfg,node,max_for_trace):
  cur_predecessor = node.predecessors
  predecessor = []
  for ele in cur_predecessor:
    predecessor.append([ele,1])
  strings = set()
  while(len(predecessor)!=0):
    predec,trace = predecessor.pop()
    have_string = testing_purposes2(predec,cfg)
    if len(have_string)>0 :
      strings.add(have_string)
      if(len(predecessor)==0):
        break
    
    elif trace<max_for_trace:
      pred_pred = predec.predecessors
      for ele in pred_pred:
        predecessor.append([ele,trace+1])
  return strings

# def get_predecessor_string2(cfg,node,max_for_trace):
#   node_vis = []
#   cur_predecessor = node.predecessors
#   predecessor = []
#   for ele in cur_predecessor:
#     if ele not in node_vis:
#       predecessor.append(ele)
#       node_vis.append(ele)
#     strings = set()
#     while(len(predecessor)!=0):
#       predec = predecessor.pop()
#       have_string = testing_purposes2(predec,cfg)
#       if len(have_string)>0 and have_string in req_strings:
#         strings.add(have_string)
#         if(len(predecessor)==0):
#           break
      
#       else :
#         pred_pred = predec.predecessors
#         for ele in pred_pred:
#           predecessor.append(ele)
#     return strings


def do_bfs(cfg,node,max_for_trace=7):
  visited.add(node)
  queue.append(node)
  while queue:
    s = queue.pop(0)
    # have_string = testing_purposes2(s,cfg)
    # flag=0
    # if have_string not in req_graph and len(have_string)>1:
    #   req_graph[have_string] = set()
    #   flag = 1
    neighbours = s.successors
    if neighbours!=None and len(neighbours)>0:
      for neighbour in neighbours:
        if neighbour not in visited:
          visited.add(neighbour)
          queue.append(neighbour)
          child_have_string = testing_purposes2(neighbour,cfg)
          if len(child_have_string)>1:
            # req_graph[have_string].add(child_have_string)
            predecessor_strings = get_predecessor_string(cfg,neighbour,max_for_trace)
            for strin in predecessor_strings:
              if strin not in req_graph:
                req_graph[strin] = set()
              req_graph[strin].add(child_have_string)


# def do_bfs2(cfg,node,max_for_trace=5):
#   child_have_string = testing_purposes2(node,cfg)
#   if len(child_have_string)>1:
#     predecessor_strings = get_predecessor_string2(cfg,node,max_for_trace)
#     if predecessor_strings==None:
#       return
#     for strin in predecessor_strings:
#       if strin not in req_graph:
#         req_graph[strin] = set()
#       req_graph[strin].add(child_have_string)

class GraphVisualization: 
   
    def __init__(self): 
          
        self.visual = [] 
          
    def addEdge(self, a, b): 
        temp = [a, b] 
        self.visual.append(temp) 
          
    def visualize(self): 
        G = nx.Graph() 
        G.add_edges_from(self.visual) 
        nx.draw_networkx(G) 
        plt.show() 



cfg,check_func,not_check_func = log_functions()
req_func = extract_call_sites(cfg,check_func)
req_strings = peephole(cfg,req_func,3)
temp = cfg.graph.nodes()
for node in temp:
  if node not in visited:
    do_bfs(cfg,node)
print(req_graph)
# G = GraphVisualization()
# for key in req_graph.keys():
#   neighbours = req_graph[key]
#   for neighbour in neighbours:
#     G.addEdge(key,neighbour)

# G.visualize()