# (c) Copyright 2021 Aaron Kimball

DBG_VERSION = [0, 1, 0]
DBG_VERSION_STR = '.'.join(map(str, DBG_VERSION))
FULL_DBG_VERSION_STR = f'Arduino Debugger (adbg) version {DBG_VERSION_STR}'

if __name__ == '__main__':
    print(FULL_DBG_VERSION_STR)
