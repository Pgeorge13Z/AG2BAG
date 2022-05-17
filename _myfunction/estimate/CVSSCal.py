from _myfunction import *

def CVSSCal(cveid):
    '''根据CVE查询AV、AC、AU'''
    file = './src/cveid.xls'
    data = xlrd.open_workbook(file)
    table = data.sheets()[0]
    cve = table.col_values(0)
    av = table.col_values(2)
    ac = table.col_values(3)
    au = table.col_values(4)

    try:
        result = cve.index(cveid)
    except:
        print('Unknown vulnerability.', cveid)
        return 1.0, 0.71, 0.704
    else:
        if av[result] == 'N':
            AV = 1.0
        elif av[result] == 'A':
            AV = 0.646
        else:
            AV = 0.359
        if ac[result] == 'L':
            AC = 0.71
        elif ac[result] == 'M':
            AC = 0.61
        else:
            AC = 0.35
        if au[result] == 'N':
            AU = 0.704
        elif au[result] == 'S':
            AU = 0.56
        else:
            AU = 0.45
        return AV, AC, AU
