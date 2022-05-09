#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from _myfunction import *

'''
作用：主函数，根据目标分析所有的关键路径，并标记各个路径的概率，找寻高危路径。
输入：攻击目标
输出：到达目标的攻击路径
'''
def A2B(aim):
    path2 = "./src/AttackGraph.xml"
    graph = readXML(path2)
    #aimShow()
    if isAimExist(graph, aim):
        print("Aim doesn't exist!")
        return 1
    DigraphAnalysis(graph, aim)
    graph = elimCir(graph, aim)
    attack_pathlist = BayesianAnalysis(graph)
    #ObservList(attack_pathlist)

    dot = dotGener(graph)
    #print(dot.source)
    dot.render('./src/output-graph.dot')

    result = resultGener(attack_pathlist)
    # print(result.source)
    result.render('./src/result.dot')
    return 0


# execCode(workStation,root)
# accessFile(workStation,write,'/usr/local/share')
# accessFile(fileServer,write,'/export'):0
# execCode(fileServer,root):0
# netAccess(fileServer,rpc,100005):0
# execCode(webServer,apache):0
# RULE 2 (remote exploit of a server program)
# _
A2B('execCode(workStation,root)')

