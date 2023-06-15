#!/usr/bin/env python3
import os
import sys
import traceback
import os.path
from datetime import datetime
from binascii import hexlify
from beacon_generate import bof_pack

DEBUGALL = True

now = datetime.now()
time_d = now.strftime("%d_%m_%Y__%H_%M_%S")
CS_EXE = "..\\bin\\coffloader.exe"
C_EXE = "w:\\COFFLoader\\coffloader64.exe"
EXE = ""

def uni( data ):
    ret = b''
    for i in data:
        ret += i.to_bytes(1,'big')
        ret += b'\x00'
    return ret

def execute( bof, format_str="", arguments=[] ):
    args = "00"
    if( len(arguments) > 0):
        args = bof_pack( format_str, arguments )
        args = hexlify(args).decode('utf-8')
    if not os.path.isdir("..\\Scripts\\results"):
        os.mkdir("..\\Scripts\\results")
    if not os.path.isdir("..\\Scripts\\results\\%s" % time_d):
        os.mkdir("..\\Scripts\\results\\%s" % time_d)
    if bof == "dir":
        cmd = EXE + " ..\\..\\..\\..\\CS-Situational-Awareness-BOF\\SA\\%s\\%s.x64.o.orig %s >> ..\\Scripts\\results\\%s\\%s.txt" % (bof, bof, args, time_d, bof)    
    else:
        cmd = EXE + " ..\\..\\..\\..\\CS-Situational-Awareness-BOF\\SA\\%s\\%s.x64.o %s >> ..\\Scripts\\results\\%s\\%s.txt" % (bof, bof, args, time_d, bof)    
    print( cmd )
    os.system( cmd )

def adcs_enum(debug=False):
    if debug == False: return
    try:
        print("[*] adcs_enum")
        execute("adcs_enum")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def adcs_enum_com(debug=False):
    if debug == False: return
    try:
        print("[*] adcs_enum_com")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def adcs_enum_com2(debug=False):
    if debug == False: return
    try:
        print("[*] adcs_enum_com2")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def adv_audit_policies(debug=False):
    if debug == False: return
    try:
        print("[*] adv_audit_policies")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def arp(debug=False):
    if debug == False: return
    try:
        print("[*] arp")
        execute("arp")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def cacls(debug=False):
    if debug == False: return
    try:
        print("[*] cacls")
        execute("cacls", "c", [uni(b".")]);
        execute("cacls", "c", [uni(b"*")]);
        execute("cacls", "c", [uni(b"C:\\windows\\system32\\notepad.exe")]);
        execute("cacls", "c", [uni(b"C:\\windows\\system32")]);
        execute("cacls", "c", [uni(b"C:\\asdf")]);
        execute("cacls", "c", [uni(b"C:\\windows\\system32\\*")]);
        execute("cacls", "c", [uni(b"C:\\windows\\system32\\asdf")]);
    except:
        print("[!] ERROR %s", traceback.print_exc())
def dir(debug=False):
    if debug == False: return
    try:
        print("[*] dir")
        execute("dir", "Zs", ["w:\\inutil_dev\\csharp\\testing\\bin\\", 2])
        execute("dir", "Zs", ["w:\\inutil_dev\\csharp\\testing\\", 2])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def driversigs(debug=False):
    if debug == False: return
    try:
        print("[*] driversigs")
        execute('driversigs')
    except:
        print("[!] ERROR %s", traceback.print_exc())
def enumLocalSessions(debug=False):
    if debug == False: return
    try:
        print("[*] enumLocalSessions")
        execute('enumLocalSessions')
    except:
        print("[!] ERROR %s", traceback.print_exc())
def enum_filter_driver(debug=False):
    if debug == False: return
    try:
        print("[*] enum_filter_driver")
        execute('enum_filter_driver', 'c', [uni(b'aut01tfan1999')])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def env(debug=False):
    if debug == False: return
    try:
        print("[*] env")
        execute("env")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def findLoadedModule(debug=False):
    if debug == False: return
    try:
        print("[*] findLoadedModule")
        execute("findLoadedModule", "cc", [b"ntdll", b"explorer"])
        execute("findLoadedModule", "cc", [b"Kernel32.dll", b"\x00"])
        execute("findLoadedModule", "cc", [b"asdfasdfadsf", b"\x00"])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def get_netsession(debug=False):
    if debug == False: return
    try:
        print("[*] get-netsession")
        execute("get-netsession", "c", [uni(b"aut01tfan1999")]);
    except:
        print("[!] ERROR %s", traceback.print_exc())
def get_password_policy(debug=False):
    if debug == False: return
    try:
        print("[*] get_password_policy")
        execute("get_password_policy", "c", [uni(b"aut01tfan1999")]);
    except:
        print("[!] ERROR %s", traceback.print_exc())
def ipconfig(debug=False):
    if debug == False: return
    try:
        print("[*] ipconfig")
        execute("ipconfig")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def ldapsearch(debug=False):
    if debug == False: return
    try:
        print("[*] ldapsearch")
        execute("ldapSearch","ccicc",[b"(objectclass=*)", b"", 0, b"", b""])
        execute("ldapSearch","ccicc",[b"(asdf=*)", b"", 248, b"", b""])
        execute("ldapSearch","ccicc",[b"(objectclass=*)", b"objectSID,name", 0, b"", b""])
        execute("ldapSearch","ccicc",[b"(objectclass=*)", b"asdf", 0, b"", b""])
        execute("ldapSearch","ccicc",[b"(objectclass=*)", b"asdf", 0, b"TrashMaster", b""])
        execute("ldapSearch","ccicc",[b"(objectclass=*)", b"asdf", 0, b"", b"TrashMaster"])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def listdns(debug=False):
    if debug == False: return
    try:
        print("[*] listdns  ")
        execute("listdns")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def listmods(debug=False):
    if debug == False: return
    try:
        print("[*] listmods")
        execute("listmods","i",[3308]); # Needs to manually be selected
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netgroup(debug=False):
    if debug == False: return
    try:
        print("[*] netgroup")
        execute('netgroup', 'scc', [0, uni(b""), uni(b"")])
        execute('netgroup', 'scc', [0, uni(b"testrange.local"), uni(b"")])
        execute('netgroup', 'scc', [0, uni(b"asdf"), uni(b"")])
        execute('netgroup', 'scc', [1, uni(b""), uni(b"Domain Admins")])
        execute('netgroup', 'scc', [1, uni(b"testrange.local"), uni(b"Domain Admins")])
        execute('netgroup', 'scc', [1, uni(b""), uni(b"asdf")])
        execute('netgroup', 'scc', [1, uni(b"asdf"), uni(b"Administrators")])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netlocalgroup(debug=False):
    if debug == False: return
    try:
        print("[*] netlocalgroup")
        execute('netlocalgroup','scc', [0,uni(b""),uni(b"")])
        execute('netlocalgroup','scc', [0,uni(b"172.31.0.1"),uni(b"")])
        execute('netlocalgroup','scc', [0,uni(b"asdf"),uni(b"")])

        execute('netlocalgroup','scc', [1, uni(b''), uni(b"Administrators")])
        execute('netlocalgroup','scc', [1, uni(b"172.31.0.1"), uni(b"Administrators")])
        execute('netlocalgroup','scc', [1, uni(b''), uni(b"asdf")])
        execute('netlocalgroup','scc', [1, uni(b"172.31.0.1"), uni(b"asdf")])
        execute('netlocalgroup','scc', [1, uni(b"asdf"), uni(b"Administrators")])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netshares(debug=False):
    if debug == False: return
    try:
        print("[*] netshares")
        execute('netshares', 'ci', [uni(b""), 0])
        execute('netshares', 'ci', [uni(b""), 1])
        execute('netshares', 'ci', [uni(b"172.31.0.1"), 0])
        execute('netshares', 'ci', [uni(b"172.31.0.1"), 1])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netstat(debug=False):
    if debug == False: return
    try:
        print("[*] netstat")
        execute("netstat")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netuse(debug=False):
    if debug == False: return
    try:
        print("[*] netuse")
        # Come back too this has many options
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netuser(debug=False):
    if debug == False: return
    try:
        print("[*] netuser")
        execute('netuser', 'cc', [uni(b"testuser"), uni(b"testrange.local")])
        execute('netuser', 'cc', [uni(b"user"), uni(b'')])
        execute('netuser', 'cc', [uni(b"dev"), uni(b'')])
        execute('netuser', 'cc', [uni(b"asdf"), uni(b'')])
        execute('netuser', 'cc', [uni(b"nopenope"), uni(b"nope")])
        execute('netuser', 'cc', [uni(b"nope"), uni(b"testrange.local")])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netuserenum(debug=False):
    if debug == False: return
    try:
        print("[*] netuserenum")
        execute('netuserenum', 'ii', [1, 1])
        execute('netuserenum', 'ii', [0, 1])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def netview(debug=False):
    if debug == False: return
    try:
        print("[*] netview")
        execute('netview', 'c', [uni(b'')])
        execute('netview', 'c', [uni(b"testrange")])
        execute('netview', 'c', [uni(b"asdf")])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def nonpagedldapsearch(debug=False):
    if debug == False: return
    try:
        print("[*] nonpagedldapsearch")
#        execute('nonpagedldapsearch', 'ccicc', [])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def nslookup(debug=False):
    if debug == False: return
    try:
        print("[*] nslookup")
#        execute('nslookup', 'ccs', [])
    except:
        print("[!] ERROR %s", traceback.print_exc())
def office_tokens(debug=False):
    if debug == False: return
    try:
        print("[*] office_tokens")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def probe(debug=False):
    if debug == False: return
    try:
        print("[*] probe")
        execute('probe', 'ci', [b"127.0.0.1", 1])
        execute('probe', 'ci', [b"127.0.0.1", 445])
        
    except:
        print("[!] ERROR %s", traceback.print_exc())
def reg_query(debug=False):
    if debug == False: return
    try:
        print("[*] reg_query")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def resources(debug=False):
    if debug == False: return
    try:
        print("[*] resources")
        execute("resources")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def routeprint(debug=False):
    if debug == False: return
    try:
        print("[*] routeprint")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_enum(debug=False):
    if debug == False: return
    try:
        print("[*] sc_enum")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_qc(debug=False):
    if debug == False: return
    try:
        print("[*] sc_qc")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_qdescription(debug=False):
    if debug == False: return
    try:
        print("[*] sc_qdescription")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_qfailure(debug=False):
    if debug == False: return
    try:
        print("[*] sc_qfailure")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_qtriggerinfo(debug=False):
    if debug == False: return
    try:
        print("[*] sc_qtriggerinfo")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def sc_query(debug=False):
    if debug == False: return
    try:
        print("[*] sc_query")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def schtasks_uacbypass(debug=False):
    if debug == False: return
    try:
        print("[*] schtasks_uacbypass")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def schtasksenum(debug=False):
    if debug == False: return
    try:
        print("[*] schtasksenum")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def schtasksquery(debug=False):
    if debug == False: return
    try:
        print("[*] schtasksquery")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def tasklist(debug=False):
    if debug == False: return
    try:
        print("[*] tasklist")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def uptime(debug=False):
    if debug == False: return
    try:
        print("[*] uptime")
        execute("uptime")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def vssenum(debug=False):
    if debug == False: return
    try:
        print("[*] vssenum")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def whoami(debug=False):
    if debug == False: return
    try:
        print("[*] whoami")
        execute("whoami")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def windowlist(debug=False):
    if debug == False: return
    try:
        print("[*] windowlist")
    except:
        print("[!] ERROR %s", traceback.print_exc())
def wmi_query(debug=False):
    if debug == False: return
    try:
        print("[*] wmi_query")
    except:
        print("[!] ERROR %s", traceback.print_exc())

if __name__=="__main__":
    if len(sys.argv) > 1: 
        EXE=C_EXE
    else:
        EXE=CS_EXE
    funcs = { 
        "adcs_enum": [adcs_enum, True],
        "adcs_enum_com": [adcs_enum_com, True],
        "adcs_enum_com2": [adcs_enum_com2, True],
        "adv_audit_policies": [adv_audit_policies, True],
        "arp": [arp, False],
        "cacls": [cacls, False],
        "dir": [dir, False],
        "driversigs": [driversigs, False],
        "enumLocalSessions": [enumLocalSessions, False],
        "enum_filter_driver": [enum_filter_driver, False],
        "env": [env, False],
        "findLoadedModule": [findLoadedModule, False],
        "get_netsession": [get_netsession, False],
        "get_password_policy": [get_password_policy, False],
        "ipconfig": [ipconfig, False],
        "ldapsearch": [ldapsearch, False],
        "listdns": [listdns, False],
        "listmods": [listmods, False],
        "netgroup": [netgroup, True],
        "netlocalgroup": [netlocalgroup, True],
        "netshares": [netshares, True],
        "netstat": [netstat, True],
        "netuse": [netuse, True],
        "netuser": [netuser, True],
        "netuserenum": [netuserenum, True],
        "netview": [netview, True],
        "nonpagedldapsearch": [nonpagedldapsearch, True],
        "nslookup": [nslookup, True],
        "office_tokens": [office_tokens, True],
        "probe": [probe, True],
        "reg_query": [reg_query, True],
        "resources": [resources, True],
        "routeprint": [routeprint, True],
        "sc_enum": [sc_enum, True],
        "sc_qc": [sc_qc, True],
        "sc_qdescription": [sc_qdescription, True],
        "sc_qfailure": [sc_qfailure, True],
        "sc_qtriggerinfo": [sc_qtriggerinfo, True],
        "sc_query": [sc_query, True],
        "schtasks_uacbypass": [schtasks_uacbypass, True],
        "schtasksenum": [schtasksenum, True],
        "schtasksquery": [schtasksquery, True],
        "tasklist": [tasklist, True],
        "uptime": [uptime, False],
        "vssenum": [vssenum, True],
        "whoami": [whoami, False],
        "windowlist": [windowlist, True],
        "wmi_query": [wmi_query, True ]
    }

    for func in funcs:
        if DEBUGALL:
            funcs[func][0](debug=True)
        else:    
            funcs[func][0](debug=funcs[func][1])
