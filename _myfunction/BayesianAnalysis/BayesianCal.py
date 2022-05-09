from _myfunction import *

'''
这一个函数模块定义了节点的概率计算方法和路径的概率计算方法，
整个模块需要之前的attacklist_Analysis.py所计算得到的路径作为输入，计算那些路径的概率
返回的是一个带有概率值的和包含高危路径的攻击路径集
'''

'''
递归计算攻击路径相对概率
输入：攻击目标节点node，和到目标的一天攻击路径subgraph
输出：这条路径的概率
'''
def RateCal(node, subgraph):

    if node.type == 'LEAF':
        return node.rate
    elif node.type == 'OR':
        parents = []
        for nod in node.prior:
            if nod in subgraph.nodgrp:
                parents.append(nod)
        rate = OrBayesian(node, parents, subgraph)
        return rate
    else:
        rate = AndBayesian(node, node.prior, subgraph)
        return rate

'''
输出：到or类型节点的概率
'''
def OrBayesian(node, parents, subgraph):
    rates = []
    for nod in parents:
        rates.append(RateCal(nod, subgraph))
    rate = 0
    i = 0
    a = []
    while i < len(rates):
        a.append(i)
        i = i + 1
    i = 0
    while i < len(rates):
        rates_temp = []
        for b in combinations(a, i):
            for j in b:
                rates_temp.append(1 - rates[j])
            for j in a:
                if j not in b:
                    rates_temp.append(rates[j])
            rate_temp = 1
            for rat in rates_temp:
                rate_temp = rate_temp * rat
            rate = rate + rate_temp
        i = i + 1
    rate = rate * node.rate
    return rate

'''
输出：到and类型节点的概率
'''
def AndBayesian(node, parents, subgraph):
    rate = node.rate
    for nod in parents:
        rate = rate * RateCal(nod, subgraph)
    return rate



'''
得到所有攻击路径及其相对概率
输入：图graph
输出：该图下的所有攻击路径和概率
'''
def BayesianAnalysis(graph):
    attack_pathlist = []
    for nod in graph.aim:
        for attacker in graph.attacker:
            attack_pathlist.append(TargetedDFS(graph, attacker, nod))

    for sublist in attack_pathlist:
        for sub in sublist:
            for nod in sub.nodgrp:
                for arc in nod.priarc:
                    for node in sub.nodgrp:
                        if node.id == arc.src:
                            sub.arcgrp.append(arc)

    for sublist in attack_pathlist:
        for subgraph in sublist:
            for nod in subgraph.aim:
                subgraph.rate = RateCal(nod, subgraph)

    return attack_pathlist

'''
找到相对攻击概率最大的攻击路径
输入：一个到攻击目标的不同路径组成的list
输出：成功概率最大的路径
'''
def seekMpath(sublist):
    temp = sublist.copy()
    tempMax = temp[-1]
    temp.pop()
    while temp:
        fol = temp[-1]
        temp.pop()
        if tempMax.rate <= fol.rate:
            tempMax = fol

    return tempMax
