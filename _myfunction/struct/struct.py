from _myfunction import *

'''
自定义了一些结构体用于后面的图分析
节点：属性有ID fact metric type,其中id和type比较重要，并在节点中附加了评估方法，在这里是CVSS
'''
# 图的节点结构
class Node:
    def __init__(self, ID, fact, metric, TYPE):
        self.id = ID
        self.fact = fact
        self.metric = metric
        self.type = TYPE
        self.cve = ''
        self.prior = []  # 节点的向前节点集
        self.next = []  # 节点的向后节点集
        self.priarc = []  # 节点的向前边集
        self.nexarc = []  # 节点的向后边集
        self.D = 0
        self.rate = 0.9  # 节点的概率
        self.flag = 0
        self.tempnext = []

    def CVSS(self, AV, AC, AU):
        self.rate = AV * AC * AU
        self.D = 1 / self.rate


# 边结构
class Edge:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.rate = 1  # 边的概率
        self.fact = ''
        self.subg = 0  # 边的向后的点的id


# 图结构
class Graph:
    def __init__(self):
        self.nodgrp = []  # 图的所有节点集合
        self.arcgrp = []  # 图的边集合
        self.attacker = []  # 攻击起点集合
        self.aim = []  # 攻击目标集合
        self.rate = 1  # 攻击路径相对概率

    def dcopy(self, graph):
        self.nodgrp = graph.nodgrp.copy()
        self.arcgrp = graph.arcgrp.copy()
        self.attacker = graph.attacker.copy()
        self.aim = graph.aim.copy()
        self.rate = graph.rate


class Stack:
    '''栈'''

    # 构造一个栈的容器
    def __init__(self):
        self.__list = []

    def PUSH(self, item):
        '''添加一个新的元素到栈顶'''
        self.__list.append(item)

    def POP(self):
        '''弹出栈顶元素'''
        return self.__list.pop()

    def peek(self):
        '''返回栈顶元素'''
        if self.__list:
            return self.__list[-1]
        return None

    def isnot_empty(self):
        '''判断栈是否为空'''
        return self.__list != []

    def size(self):
        '''返回栈的的元素个数'''
        return len(self.__list)

    def clr(self):
        '''清空栈'''
        return self.__list.clear()

    def copy(self):
        '''返回栈体'''
        return self.__list.copy()

    def dcopy(self, l):
        '''直接拷贝一个list为栈体'''
        self.__list = l.copy()

    def remove(self, nod):
        '''去除栈体中某个节点'''
        while nod in self.__list:
            self.__list.remove(nod)
