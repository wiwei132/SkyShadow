import os
import re
import sys

# DLL劫持挖掘
def GetPayload(path, exeName):
    whiteDLLs = {}
    exeFullPath = path + '\\' + exeName
    # 获取导入表
    imports = os.popen('dumpbin /imports "' + exeFullPath + '"').read()
    # 匹配DLL信息
    dlls = re.findall('[\S]+\.[dllDLL]{3}[\s\S]+?\n\n[\s\S]+?\n\n', imports)
    for dll in dlls:
        if '?' not in dll:
            dllName = re.findall('[\S]+\.[dllDLL]{3}', dll)[0]
            # 排除微软DLL
            exist = False
            for msDLL in msDLLs:
                if msDLL.lower() == dllName.lower():
                    exist = True
                    break
            if not exist:
                dllFunctions = re.findall('\n\n[\s\S]+', dll)[0]
                dllFunctions = re.findall('[0-9A-F][\s]([\S]+)\n', dllFunctions)
                whiteDLLs[dllName] = dllFunctions
    # 生成Payload
    if whiteDLLs:
        print(exeFullPath)
        # 获取EXE信息
        exeSize = os.path.getsize(exeFullPath)
        if exeSize > 1048576:
            exeSize = str(round(exeSize/1048576, 2)) + 'MB'
        elif exeSize > 1024:
            exeSize = str(round(exeSize/1024, 2)) + 'KB'
        else:
            exeSize = str(round(exeSize, 2)) + 'B'
        sigcheck = os.popen('sigcheck64 "' + exeFullPath + '"').read()
        exeMachineType = re.findall('MachineType:[\s]+([\S]+)', sigcheck)[0]
        if exeMachineType == '64-bit':
            bit = 'x64'
        else:
            bit = 'x86'
        exePublisher = re.findall('Publisher:[\s]+([\S]+)', sigcheck)[0]
        if exePublisher == 'n/a':
            signature = ''
            payload = [bit + ' ' + exeSize + ' 无数字签名 ' + exeName]
        else:
            signature = '数字签名'
            payload = [bit + ' ' + exeSize + ' 有数字签名 ' + exeName]
        # 生成导出函数
        for dllName, dllFunctions in whiteDLLs.items():
            payload += ['\n' + dllName]
            for dllFunction in dllFunctions:
                payload += ['extern "C" __declspec(dllexport) int ' + dllFunction + '() {\n    return 0;\n}']
        # 写入文件
        name = bit + ' ' + exeSize + ' ' + signature + ' ' + exeName
        try:
            os.mkdir('Payload')
        except:
            pass
        try:
            os.mkdir('Payload\\' + name)
        except:
            pass
        with open('Payload\\' + name + '\\' + name + '.txt', 'w') as f:
            f.write('\n'.join(payload))
        os.popen('copy "' + exeFullPath + '" "' + os.getcwd() + '\\Payload\\' + name + '"')

# 遍历目录
def Collect(path):
    try:
        for fileName in os.listdir(path):
            if os.path.isfile(path + '\\' + fileName): # 文件
                if fileName[-4:] == '.exe':
                    GetPayload(path, fileName) # DLL劫持挖掘
            elif os.path.isdir(path + '\\' + fileName): # 文件夹
                Collect(path + '\\' + fileName)
    except:
        pass

# 获取微软DLL
with open('MS DLL.txt','r') as f:
    msDLLs = f.read().splitlines()

# 收集EXE
if len(sys.argv) == 2:
    Collect(sys.argv[1])
else:
    print('Usage: python scan.py "D:\\\\"')