import angr
import claripy
import sys
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
    if "print" in func.name:
      check_func.add(addr)
    elif 'syslog' in func.name:
      check_func.add(addr)
    else:
      not_check_func.add(addr)
  return cfg,check_func,not_check_func

def foo(cfg,addr):
  req_strings = []
  try:
    entry_func = cfg.kb.functions[addr]
  except :
    print("do nothing about it")
  else:
    try:
      temp_string = entry_func.string_references(vex_only=True)
    except:
      print("")
    else:
      for addr,string in temp_string:
        req_strings.append(string)
      return req_strings
    return req_strings
  return req_strings

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



def check(cfg,address):
  req_string = set()
  try:
    state = proj.factory.blank_state(addr = address)
  except TypeError:
    print("do nothing")
  else: 
    succ = state.step()
    for st in succ.successors:
      # print(st.addr)
      addr = st.regs.rdi
      bvv = state.memory.load(addr,14)
      temp = state.solver.eval(bvv,cast_to=bytes)
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
      l = foo(cfg,addr)
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
        if predecessors!=None:
          predec = []
          for predecessor in predecessors:
            predec.append(predecessor)
          temp_predec = tuple(predec)
          set_call.add((temp_predec,back_trace+1))

  return req_string

# def refere(cfg,add):
#   for addr in check_func:
#     entry_func = cfg.kb.functions[addr]
#     try:
#       temp = entry_func.string_references()
#     except:
#       print("hoho")
#     else:
#       print(temp)

# def testing():
#   state = proj.factory.entry_state()
#   simgr = proj.factory.simulation_manager(state)
#   simgr.explore(find =lambda s: len(s.posix.dumps(1))>0 )
#   for st in simgr.found:
#     print(st.posix.dumps(1))

def printingxrefs(cfg,funct):
   st = proj.factory.entry_state()
   obj = cfg.kb.xrefs
   for f in funct:
    addr = obj.get_xrefs_by_ins_addr(f)
    temp = st.memory.load(0x400520, 10)
    ans = st.solver.eval(temp,cast_to=bytes)
    print(addr)
    print(ans)

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

  return ''.join(out)


strcnt = itertools.count()

def random(cfg):
  state = proj.factory.blank_state()
  string_references = []
  for v in cfg._memory_data.values():
      if v.sort == "string" and v.size > 1:
          st = state.solver.eval(state.memory.load(v.address, v.size), cast_to=bytes)
          string_references.append((v.address, st))

  strings = [] if len(string_references) == 0 else list(list(zip(*string_references))[1])

  valid_strings = []
  if len(strings) > 0:
      for s in strings:
          if len(s) <= 128:
              valid_strings.append(s)
        
  for s in set(valid_strings):
      s_val = hexescape(s)
      print("string_%d=\"%s\"" % (next(strcnt), s_val))

st = proj.factory.entry_state()

def testing_purposes(addr,cfg):
  entry_func = cfg.kb.functions[addr]
  bbs = entry_func.blocks
  for bb_addr in bbs:
    try:
      ins_addr = bb_addr.instruction_addrs
    except:
      continue
    else:
      starting = min(ins_addr)
      ending = max(ins_addr)
      references = cfg.kb.xrefs
      temp = references.get_xrefs_by_ins_addr_region(starting, ending)
      tmp = list(temp)
      for temptmp in tmp:
        t = temptmp.memory_data
        if t!=None and 'string' in t.sort and t.size>1:
          req_addr = t.address
          yeah = st.memory.load(req_addr,t.size-1)
          print(st.solver.eval(yeah,cast_to=bytes))

# def testing_purposes2(node,cfg):
#   try:
#     cfg_node = cfg.get_any_node(node.addr)
#     ins_addr = cfg_node.instruction_addrs
#   except:
#     return ''
#   else:
#     if(len(ins_addr)>0):
#       starting = min(ins_addr)
#       ending = max(ins_addr)
#       references = cfg.kb.xrefs
#       temp = references.get_xrefs_by_ins_addr_region(starting, ending)
#       tmp = list(temp)
#       for temptmp in tmp:
#         t = temptmp.memory_data
#         if t!=None and 'string' in t.sort and t.size>1:
#           req_addr = t.address
#           yeah = st.memory.load(req_addr,t.size-1)
#           temp_string = st.solver.eval(yeah,cast_to=bytes).decode("utf-8")
#           if temp_string in req_strings:
#             return temp_string
#           return(st.solver.eval(yeah,cast_to=bytes))
#   return ''

def testing_purposes2(node,cfg):
  try:
    cfg_node = cfg.get_any_node(node.addr)
    ins_addr = cfg_node.instruction_addrs
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

# def get_predecessor_string(cfg,node,max_for_trace=15):
#   cur_predecessor = node.predecessors
#   predecessor = []
#   for ele in cur_predecessor:
#     predecessor.append([ele,1])
#   strings = set()
#   while(len(predecessor)!=0):
#     predec,trace = predecessor.pop()
#     have_string = testing_purposes2(predec,cfg)
#     if len(have_string)>0 and have_string in req_strings:
#       strings.add(have_string)
#       if(len(predecessor)==0):
#         break
    
#     elif trace<max_for_trace:
#       pred_pred = predec.predecessors
#       for ele in pred_pred:
#         predecessor.append([ele,trace+1])
#   return strings

def get_predecessor_string2(cfg,node,G,entry,exits):
  node_vis = []
  cur_predecessor = list(G.predecessors(node))
  predecessor = []
  for ele in cur_predecessor:
    if ele not in node_vis:
      predecessor.append(ele)
      node_vis.append(ele)
  strings = set()
  while(len(predecessor)!=0):
    predec = predecessor.pop()
    have_string = testing_purposes2(predec,cfg)
    if (len(have_string)>0 and have_string in req_strings) or (predec.addr in exits) or (predec.addr==entry):
      strings.add((predec.addr,have_string))
      if(len(predecessor)==0):
        break
    
    else :
      pred_pred = list(G.predecessors(predec))
      for ele in pred_pred:
        if ele not in node_vis:
          node_vis.append(ele)
          predecessor.append(ele)
  return strings

#Add dummy nodes
def do_bfs(G,node,cfg,entry,exits):
  
  visited.add(node)
  queue.append(node)
  while queue:
    s = queue.pop(0)
    # have_string = testing_purposes2(s,cfg)
    # if have_string not in req_graph and len(have_string)>1:
    #   req_graph[have_string] = set()
    neighbours = list(G.successors(s))
    if neighbours!=None and len(neighbours)>0:
      for neighbour in neighbours:
        if neighbour not in visited:
          visited.add(neighbour)
          queue.append(neighbour)
          child_have_string = testing_purposes2(neighbour,cfg)
          child_node = (neighbour.addr,child_have_string)

          if len(child_have_string)>1 or (neighbour.addr in exits) or (neighbour.addr==entry):
            if child_node not in req_graph:
              req_graph[child_node] = set()
            predecessor_strings = get_predecessor_string2(cfg,neighbour,G,entry,exits)
            for strin in predecessor_strings:
              if strin not in req_graph:
                req_graph[strin] = set()
              req_graph[strin].add(child_node)

  # for exit_addr in exits:
  #   exit_node = cfg.get_any_node(exit_addr)
  #   exit_str = testing_purposes2(exit_node,cfg)
  #   exit_node_str = (exit_addr,exit_str)
  #   if exit_node_str not in req_graph:
  #     req_graph[exit_node_str] = set()

  return req_graph

# def do_bfs2(G,node,cfg):
#   child_have_string = testing_purposes2(node,cfg)
#   if len(child_have_string)>1:
#     predecessor_strings = get_predecessor_string2(cfg,node,G)
#     if predecessor_strings==None:
#       return
#     for strin in predecessor_strings:
#       if strin not in req_graph:
#         req_graph[strin] = set()
#       req_graph[strin].add(child_have_string)
#   return req_graph

class GraphVisualization: 
   
    def __init__(self): 
          
        # visual is a list which stores all  
        # the set of edges that constitutes a 
        # graph 
        self.visual = [] 
          
    # addEdge function inputs the vertices of an 
    # edge and appends it to the visual list 
    def addEdge(self, a, b): 
        temp = [a, b] 
        self.visual.append(temp) 
          
    # In visualize function G is an object of 
    # class Graph given by networkx G.add_edges_from(visual) 
    # creates a graph with a given list 
    # nx.draw_networkx(G) - plots the graph 
    # plt.show() - displays the graph 
    def visualize(self): 
        G = nx.Graph() 
        G.add_edges_from(self.visual) 
        nx.draw_networkx(G) 
        plt.show() 


def create_subgraph(G,cfg,entry,exits):
  visited.clear()
  req_graph.clear()
  nodes = list(G.nodes)
  for node in nodes:
    if node not in visited:
      do_bfs(G,node,cfg,entry,exits)
  temp_graph = req_graph.copy()
  return temp_graph

def convert_graph_to_dict(G):
  graph = {}
  nodes = list(G.nodes)
  if len(nodes)==0:
    return graph
  else:
    vis = set()
    queue = set()
    start_node = nodes[2]
    vis.add(start_node)
    queue.add(start_node)
    while queue:
      s = queue.pop()
      parent_string = testing_purposes2(s,cfg)
      parent_node = (s.addr,parent_string)
      if parent_node not in graph:
        graph[parent_node] = set()
      for n in list(G.successors(s)):
        if n not in vis:
          child_string = testing_purposes2(n,cfg)
          child_node = (n.addr,child_string)
          graph[parent_node].add(child_node)
          queue.add(n)
          vis.add(n)
    return graph


subgraph_dict = {}
def build_lms_path(cfg,not_check_func):
  for fun in not_check_func:
    exits = set()
    entry_func = cfg.kb.functions[fun]
    func_bbs = entry_func.block_addrs
    returns =  entry_func.get_call_sites()
    for keys in returns:
      exits.add(keys)
    exits.add(max(func_bbs))
    entry =  min(func_bbs)
    graph = entry_func._local_transition_graph
    subgraph_graph = create_subgraph(graph,cfg,entry,exits)

    # if(len(subgraph_graph)>=0):
    #   if func not in subgraph_dict:
    #     exit_graph_tuple = (exits,subgraph_graph)
    #     subgraph_dict[func] = exit_graph_tuple

    if(len(subgraph_graph)>0):
      exit_graph_tuple = (exits,subgraph_graph)
      subgraph_dict[entry_func.addr] = exit_graph_tuple


#Check why nothing is entering in the if block
def connect_subgraph(subgraph_dict,cfg):
  key_subgraph_dict = list(subgraph_dict.keys())
  for func_addr in subgraph_dict:
    exit_list = subgraph_dict[func_addr][0]
    subgraph = subgraph_dict[func_addr][1]
    subgraph_keys = list(subgraph.keys())
    # print(subgraph)
    entry_func = cfg.kb.functions[func_addr]
    for exit_addr in exit_list:
      exit_cfg_node = cfg.get_any_node(exit_addr)
      exit_succs = exit_cfg_node.successors
      if len(exit_succs)==0:
        continue
      else:
        exit_succ = exit_succs[0]
        exit_str = testing_purposes2(exit_cfg_node,cfg)
        exit_node = (exit_addr,exit_str)
        if (exit_node in subgraph_keys) and (exit_succ.addr in key_subgraph_dict):
          succ_keys = list(subgraph_dict[exit_succ.addr][1].keys())
          for key in succ_keys:
            subgraph[exit_node].add(key)
    print(subgraph)





# cfg,check_func = log_functions()
# for addr in check_func:
#   testing_purposes(addr,cfg)
# random(cfg)
cfg,check_func,not_check_func = log_functions()
print(check_func)
req_func = extract_call_sites(cfg,check_func)
req_strings = peephole(cfg,req_func,3)
build_lms_path(cfg,not_check_func)
connect_subgraph(subgraph_dict,cfg)
# connect_subgraph(subgraph_dict,cfg)
# for func in check_func:
#   entry_func = cfg.kb.functions[func]
#   for bbs in entry_func.block_addrs:
#     start_bbs = min(start_bbs,bbs)
# print(req_strings)
# for addr in not_check_func:
#   testing_purposes(addr,cfg)


# temp = cfg.graph.nodes()
# lst = []
# for node in temp:
#   do_bfs2(cfg,node)
# print(req_graph)

# G = cfg.graph
# sub_G = G.__class__()
# sub_G = create_subgraph(cfg,sub_G)
# print(nx.to_dict_of_dicts(sub_G,list(sub_G.nodes)))
# final_graph = convert_graph_to_dict(sub_G)
# print(final_graph)


# G = GraphVisualization()
# for key in req_graph.keys():
#   neighbours = req_graph[key]
#   for neighbour in neighbours:
#     G.addEdge(key,neighbour)

# G.visualize()
# print(req_graph)
# printingxrefs(cfg,check_func)
# req_func = extract_call_sites(cfg,check_func)
# # print(req_func)
# req_strings = peephole(cfg,check_func,3)
# print(req_strings)
# # print(foo(cfg,req_func))
# for addr in check_func:
#   print(foo(cfg,addr))
# testing()
