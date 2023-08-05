import os

# 遍历目录
def Collect(path):
    try:
        for fileName in os.listdir(path):
            if os.path.isfile(path + '\\' + fileName): # 文件
                if fileName[-4:] == '.dll':
                    print(fileName)
                    msDLLs.add(fileName)
            elif os.path.isdir(path + '\\' + fileName): # 文件夹
                Collect(path + '\\' + fileName)
    except:
        pass

msDLLs = set()

# 收集微软DLL
Collect('C:\Windows\System32')
Collect('C:\Windows\SysWOW64')
Collect('C:\Windows\WinSxS')

# 写入文件
with open('MS DLL.txt', 'w') as f:
    f.write('\n'.join(msDLLs))