
from _myfunction import *

def dotGener(graph):
    dot = Digraph(comment='This is a attack_graph.', name="Bayesian Attack Graph")
    dot.node("Bayesian Attack Graph", "Bayesian Attack Graph", shape='tripleoctagon', color='blue')
    for nod in graph.nodgrp:
        if nod.type == 'LEAF':
            dot.node(nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='box')
        elif nod.type == 'OR':
            dot.node(nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='diamond')
        elif nod.type == 'AND':
            dot.node(nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='ellipse')
    for arc in graph.arcgrp:
        dot.edge(arc.src, arc.dst, label=arc.fact + ':' + arc.subg)

    return dot



def resultGener(attack_pathlist):
    dot = Digraph(comment='This is the result.', name="cluster_Attack_Paths")
    dot.attr(compound='true')
    dot.node("Attack Paths", "Bayesian Attack Paths", shape='note', color='blue')
    # i = 64
    i = 0
    for sublist in attack_pathlist:
        sdot = Digraph(name='cluster_Series' + ':' + str(i + 1))
        sdot.attr(compound='true')
        for subgraph in sublist:
            n = 0
            i = i + 1
            if subgraph.rate == seekMpath(sublist).rate:
                subdot = Digraph(graph_attr={"style": 'filled', "color": 'lemonchiffon2'},
                                 node_attr={"style": "filled", "color": "lightpink"},
                                 comment='This is the attack graph with high risk.',
                                 name="cluster_rate" + ":" + str(i))
            else:
                subdot = Digraph(name='cluster_rate' + ':' + str(i))
            for nod in subgraph.nodgrp:
                n = n + 1
            n=44
           # print(n)
            matrix = [[0 for i in range(n)] for i in range(n)]
            for nod in subgraph.nodgrp:
                if nod.type == 'LEAF':
                    subdot.node(str(i) + '|' + nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='box')
                elif nod.type == 'OR':
                    subdot.node(str(i) + '|' + nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='diamond')
                elif nod.type == 'AND':
                    subdot.node(str(i) + '|' + nod.id, nod.id + ":" + nod.fact + ":" + nod.metric, shape='ellipse')
            for arc in subgraph.arcgrp:
                subdot.edge(str(i) + '|' + arc.src, str(i) + '|' + arc.dst, label=arc.fact + ':' + arc.subg)
               # print(int(arc.src)-1)
               # print(int(arc.dst)-1)
                matrix[int(arc.src)-1][int(arc.dst)-1] = 1
            subdot.node("Rate" + str(i), "Relative Rate:" + str(subgraph.rate), shape='doubleoctagon', color='brown1')
            subdot.node("attack graph with high risk", "attack graph with high risk", shape='octagon', color='red')
            for nod in subgraph.aim:
                subdot.edge(str(i) + '|' + nod.id, "Rate" + str(i), arrowhead='dot', style='dashed')
        #   print(matrix)
            # subdot.view()
            sdot.subgraph(subdot)
        # sdot.view()
        dot.subgraph(sdot)
        dot.view()

    return dot
