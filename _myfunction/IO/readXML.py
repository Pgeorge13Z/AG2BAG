from _myfunction import *

'''
input文件，调用python的readXML库，从地址读取文件生成有向图，若输入文件更改，此部分需要进行相应的更改
输入：XML文件的地址
输出：有向图
'''
def readXML(path):
    '''读取XML文件生成有向图'''
    domTree = parse(path) #打开XML文档
    rootNode = domTree.documentElement #根据xml文档，得到文档元素的对象
    print(rootNode.nodeName)

    arcs = rootNode.getElementsByTagName("arcs")
    vertices = rootNode.getElementsByTagName("vertices")

    arclist = arcs[0].getElementsByTagName("arc")
    vertexlist = vertices[0].getElementsByTagName("vertex")

    graph = Graph() #自定义的结构体graph

    for vertex in vertexlist:
        ID = vertex.getElementsByTagName("id")[0].childNodes[0].data
        fact = vertex.getElementsByTagName("fact")[0].childNodes[0].data
        metric = vertex.getElementsByTagName("metric")[0].childNodes[0].data
        TYPE = vertex.getElementsByTagName("type")[0].childNodes[0].data
        nod = Node(ID, fact, metric, TYPE)
        graph.nodgrp.append(nod)

    for arc in arclist:
        dst = arc.getElementsByTagName("src")[0].childNodes[0].data
        src = arc.getElementsByTagName("dst")[0].childNodes[0].data
        ar = Edge(src, dst)
        graph.arcgrp.append(ar)

    return graph
