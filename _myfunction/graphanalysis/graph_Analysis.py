from _myfunction import *

'''
这一个函数模块是对攻击图进行处理
在DigraphAnalysis（）函数中对节点和边进行关联，
在elimCir()函数中对图进行消环等操作
'''


'''
解析图，将图的边与节点关联，节点相互关联并分类，根据攻击目标丰富图属性
输入：图和目标
输出：无输出，完善结构体内容:节点完善前后节点集和边集，叶子节点改变结构，图增加攻击目标和攻击起点，边加入fact（即节点的type）
'''

def DigraphAnalysis(graph, aim):

    for nod in graph.nodgrp:
        for arc in graph.arcgrp:
            if arc.src == nod.id:
                for node in graph.nodgrp:
                    if node.id == arc.dst:
                        nod.next.append(node)
                nod.nexarc.append(arc)
            elif arc.dst == nod.id:
                for node in graph.nodgrp:
                    if node.id == arc.src:
                        nod.prior.append(node)
                nod.priarc.append(arc)
                arc.subg = nod.id
                if nod.type == 'AND':
                    arc.fact = 'and'
                elif nod.type == 'OR':
                    arc.fact = 'or'

    for nod in graph.nodgrp:
        if nod.type == 'LEAF':
            if nod.fact.find('vulExists') != -1:
                fact = nod.fact
                fact = fact.split(',')
                if fact[1] == 'vulID':
                    nod.cve = fact[1]
                else:
                    cve = fact[1].split('\'')
                    nod.cve = cve[1]
            elif nod.fact.find('attacker') != -1:
                graph.attacker.append(nod)
        elif aim == '_':
            if nod.type == 'OR':
                graph.aim.append(nod)
        elif aim != '':
            if nod.fact.find(aim) != -1:
                if nod.type == 'OR':
                    graph.aim.append(nod)

    tempGnodgrp = graph.nodgrp.copy()
    tempGattacker = graph.attacker.copy()
    # 用一个新的id的节点代替该叶子节点
    for nod in tempGnodgrp:
        if nod.type == 'LEAF':
            tempid = 1
            while len(nod.next) > 1:
                node = Node(str(tempid) + '|' + nod.id, nod.fact, nod.metric, nod.type)
                tempnext = nod.next.pop()
                node.next.append(tempnext)
                tempNnexarc = nod.nexarc.copy()
                for arc in tempNnexarc:
                    if arc.dst == tempnext.id:
                        nod.nexarc.remove(arc)
                        arc.src = str(tempid) + '|' + nod.id
                        node.nexarc.append(arc)
                tempnext.prior.remove(nod)
                tempnext.prior.append(node)
                graph.nodgrp.append(node)
                if nod in tempGattacker:
                    graph.attacker.append(node)
                tempid = tempid + 1

'''
删除一个AND节点
输入:graph nod
输出:删除AND节点后，更新结构的graph
'''
def elimAND(graph, nod):
    tempnods = nod.next.copy()
    temp = nod.next.copy()
    for node in temp:
        node.prior.remove(nod)
        nod.next.remove(node)
    temp = nod.prior.copy()
    for node in temp:
        if node.type == 'LEAF':
            graph.nodgrp.remove(node)
            node.next.remove(nod)
            nod.prior.remove(node)
        else:
            node.next.remove(nod)
            nod.prior.remove(node)

    for arc in (nod.priarc + nod.nexarc):
        graph.arcgrp.remove(arc)
    graph.nodgrp.remove(nod)

    for temp in tempnods:
        if temp.prior:
            pass
        else:
            graph = elimOR(graph, temp)

    return graph

'''
删除一个OR节点的子节点
输入:graph nod
输出:删除OR节点的子节点后，更新结构的graph
'''
def elimFollOR(graph, nod):
    temp = nod.next.copy()
    for node in temp:
        graph = elimAND(graph, node)

    return graph

'''
    删除一个OR节点
    输入:graph nod
    输出:删除OR节点后，更新结构的graph
'''
def elimOR(graph, nod):
    graph = elimFollOR(graph, nod)
    graph.nodgrp.remove(nod)

    return graph


'''
标记一个AND区域
'''
def Dye(nod):

    for nd in nod.prior:
        nd.flag = 1

'''
在一个list中寻找一个环路
输入:stack
输出:存在的环路cir,和布尔值exist
'''
def seekCir(stack):
    cir = []
    exist = 0
    temp = Stack()
    temp.dcopy(stack)
    flag = temp.peek()
    if flag.type == 'AND':
        cir.append(flag)
    temp.POP()
    while temp.isnot_empty():
        check = temp.peek()
        if check.type == 'AND':
            cir.append(check)
        temp.POP()
        if check == flag:
            exist = 1
            break

    return cir, exist

'''
通过去除攻击难度最大的AND节点来消除含圈路径
输入:graph和环路
输出:消环后的图
'''
def cutCir(graph, cir):

    tempMax = cir[0]
    graph = elimAND(graph, tempMax)

    return graph

'''
深度优先搜索从某一攻击起点开始的所有可能路径并消除含圈路径
输入:graph和叶子节点
输出:消除环路后的图
'''
def DFScut(graph, leaf):
    stack = Stack()
    stack.PUSH(leaf)
    while stack.isnot_empty():
        if stack.peek().tempnext:
            temp = stack.peek().tempnext[-1]
            stack.peek().tempnext.pop()
            if temp.type == 'AND':
                Dye(temp)
            stack.PUSH(temp)
            cir, exist = seekCir(stack)
            if exist:
                graph = cutCir(graph, cir)
                for node in stack.copy():
                    if node not in graph.nodgrp:
                        stack.remove(node)
        else:
            stack.POP()

    return graph

'''
消除整个图的含圈路径
输入:graph aim
输出:消除环路后的图
'''
def elimCir(graph, aim):
    temp = graph.nodgrp.copy()
    if aim == '_':
        pass
    else:
        for nod in temp:
            if nod.fact == aim:
                graph = elimFollOR(graph, nod)

    for nod in graph.nodgrp:
        if nod.type == 'LEAF':
            if nod.cve:
                AV, AC, AU = CVSSCal(nod.cve)
                nod.CVSS(AV, AC, AU)
        if nod.type == 'AND':
            nod.rate = 1

    for node in graph.nodgrp:
        node.tempnext = node.next.copy()
    temp = graph.attacker.copy()
    for node in temp:
        for nod in node.next:
            Dye(nod)
        graph = DFScut(graph, node)
    temp = graph.nodgrp.copy()
    for node in temp:
        if (node.type == 'LEAF') & (node.flag == 0):
            for nod in node.next:
                Dye(nod)
            graph = DFScut(graph, node)

    return graph
