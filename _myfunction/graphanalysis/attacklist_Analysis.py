from _myfunction import *

'''
这一个函数模块定义了一些对于获取攻击路径的方法，为之后计算高危路径概率作准备，
并定义了一些展示函数，可以展示攻击起点 攻击目标 攻击路径
'''

'''
初始化已标记主路径外的所有节点标记
输入:graph stack
输出:无输出，对输入的图和栈的节点初始化
'''
def InitExceptStack(graph, stack):
    for nod in graph.nodgrp:
        if nod not in stack.copy():
            nod.flag = 0
            nod.tempnext = nod.next.copy()

'''
先找到一条主线，再将路上所有节点的祖先节点全部包含进来
输入:graph 要找寻的攻击子图 和该子图下的一个and节点
输出:无输出，补充到该目标的攻击路径，补充路上所有节点的祖先节点
'''

def eatAcient(graph, subgraph, node):
    if node.prior:
        for nod in node.prior:
            if nod.flag == 0:
                if nod.type == 'LEAF':
                    subgraph.nodgrp.append(nod)
                    nod.flag = 1
                else: #不是and或leaf 则是or
                    subsubgraphs = []
                    for attacker in graph.attacker:
                        graph_copy = Graph()
                        graph_copy.dcopy(graph)
                        subsubgraphs = subsubgraphs + TargetedDFS(graph_copy, attacker, nod)
                    for fragment in subsubgraphs:
                        for nd in fragment:
                            subgraph.nodgrp.append(nd)

'''
深度优先搜索找到一个起点到终点的所有攻击路径
输入:graph 攻击起点 攻击终点
输出:该起点到该终点的全部攻击路径
'''
def TargetedDFS(graph, attacker, terminal):
    stack = Stack()
    InitExceptStack(graph, stack)
    stack.PUSH(attacker)
    attacker.flag = 1
    subgraphlist = []
    while stack.isnot_empty():
        if stack.peek().tempnext:
            temp = stack.peek().tempnext[-1]
            stack.peek().tempnext.pop()
            temp.flag = 1
            stack.PUSH(temp)
        else:
            temp = stack.peek()
            if temp.type == 'OR':
                if temp == terminal:
                    subgraph = Graph()
                    subgraph.aim.append(temp)
                    subgraph.attacker.append(attacker)
                    subgraph.nodgrp = stack.copy()
                    temp = subgraph.nodgrp.copy()
                    for nod in temp:
                        if nod.type == 'AND':
                            eatAcient(graph, subgraph, nod)
                    subgraph.nodgrp = list(set(subgraph.nodgrp))
                    subgraphlist.append(subgraph)
            stack.POP()
            InitExceptStack(graph, stack)

    return subgraphlist


'''
展示全部攻击路径
输入:攻击路径集
输出:所有的路径 节点集和边集
'''
def ObservList(attack_pathlist):
    for sublist in attack_pathlist:
        print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
        for sub in sublist:
            print('-------------------------------------------')
            for nod in sub.nodgrp:
                print(nod.id, ':', nod.fact)
            print('-------------------------')
            for arc in sub.arcgrp:
                print(arc.src, '->', arc.dst)
            print('-------------------------------------------')

'''
展示目标集
输入:攻击图的xml文件
输出:图里的可以攻击的目标
'''
def aimShow():
    aimlist = []
    path = "./src/AttackGraph.xml"
    graph = readXML(path)
    for nod in graph.nodgrp:
        if nod.type == 'OR':
            aimlist.append(nod.fact)
            print(nod.fact)


'''
判断目标是否在图中存在
输入：图和目标
输出：存在输出true，不存在输出false
'''

def isAimExist(graph, aim):
    flag = True
    for nod in graph.nodgrp:
        if nod.type == 'OR':
            if nod.fact.find(aim) != -1:
                flag = False
    if (aim == '') | (aim == '_'):
        flag = False

    return flag
