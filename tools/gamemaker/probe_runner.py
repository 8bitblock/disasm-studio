"""Owned-process, bounded native breakpoint probe for the exact Nubby runner.

The installed EXE/archive are never modified. The launched process is terminated
after collecting the requested snapshots. Do not use alongside another debugger.
"""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import struct
import time

from runner_inspect import DEFAULT_EXE, PE
from pathlib import Path

K = C.WinDLL("kernel32", use_last_error=True)
SIZE = C.c_size_t
PTR = C.c_void_p
U64 = C.c_uint64


class STARTUPINFO(C.Structure):
    _fields_ = [("cb",W.DWORD),("reserved",W.LPWSTR),("desktop",W.LPWSTR),
        ("title",W.LPWSTR),("x",W.DWORD),("y",W.DWORD),("xs",W.DWORD),
        ("ys",W.DWORD),("xc",W.DWORD),("yc",W.DWORD),("fill",W.DWORD),
        ("flags",W.DWORD),("show",W.WORD),("res2",W.WORD),("reserved2",PTR),
        ("stdin",PTR),("stdout",PTR),("stderr",PTR)]


class PROCESSINFO(C.Structure):
    _fields_ = [("process",PTR),("thread",PTR),("pid",W.DWORD),("tid",W.DWORD)]


K.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,PTR,PTR,W.BOOL,W.DWORD,PTR,W.LPCWSTR,C.POINTER(STARTUPINFO),C.POINTER(PROCESSINFO)]
K.CreateProcessW.restype=W.BOOL
K.WaitForDebugEvent.argtypes=[PTR,W.DWORD]; K.WaitForDebugEvent.restype=W.BOOL
K.ContinueDebugEvent.argtypes=[W.DWORD,W.DWORD,W.DWORD]; K.ContinueDebugEvent.restype=W.BOOL
K.ReadProcessMemory.argtypes=[PTR,PTR,PTR,SIZE,C.POINTER(SIZE)]; K.ReadProcessMemory.restype=W.BOOL
K.WriteProcessMemory.argtypes=[PTR,PTR,PTR,SIZE,C.POINTER(SIZE)]; K.WriteProcessMemory.restype=W.BOOL
K.VirtualProtectEx.argtypes=[PTR,PTR,SIZE,W.DWORD,C.POINTER(W.DWORD)]; K.VirtualProtectEx.restype=W.BOOL
K.FlushInstructionCache.argtypes=[PTR,PTR,SIZE]; K.FlushInstructionCache.restype=W.BOOL
K.GetThreadContext.argtypes=[PTR,PTR]; K.GetThreadContext.restype=W.BOOL
K.SetThreadContext.argtypes=[PTR,PTR]; K.SetThreadContext.restype=W.BOOL
K.OpenThread.argtypes=[W.DWORD,W.BOOL,W.DWORD]; K.OpenThread.restype=PTR
K.TerminateProcess.argtypes=[PTR,W.UINT]; K.TerminateProcess.restype=W.BOOL
K.DebugActiveProcessStop.argtypes=[W.DWORD]; K.DebugActiveProcessStop.restype=W.BOOL
K.CloseHandle.argtypes=[PTR]; K.CloseHandle.restype=W.BOOL
K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=PTR
K.DebugActiveProcess.argtypes=[W.DWORD];K.DebugActiveProcess.restype=W.BOOL
K.DebugBreakProcess.argtypes=[PTR];K.DebugBreakProcess.restype=W.BOOL
K.DebugSetProcessKillOnExit.argtypes=[W.BOOL];K.DebugSetProcessKillOnExit.restype=W.BOOL

REGS = {"rax":120,"rcx":128,"rdx":136,"rbx":144,"rsp":152,"rbp":160,
        "rsi":168,"rdi":176,"r8":184,"r9":192,"r10":200,"r11":208,
        "r12":216,"r13":224,"r14":232,"r15":240,"rip":248}


def checked(ok, operation):
    if not ok: raise OSError(C.get_last_error(), operation)


class Context:
    def __init__(self, thread):
        self.storage=C.create_string_buffer(1248)
        self.address=(C.addressof(self.storage)+15)&~15
        C.c_uint32.from_address(self.address+48).value=0x10001f
        checked(K.GetThreadContext(thread,self.address),"GetThreadContext")
    def get(self,name): return U64.from_address(self.address+REGS[name]).value
    def set(self,name,value): U64.from_address(self.address+REGS[name]).value=value
    def flags(self,value=None):
        v=C.c_uint32.from_address(self.address+68)
        if value is not None:v.value=value
        return v.value
    def write(self,thread): checked(K.SetThreadContext(thread,self.address),"SetThreadContext")
    def registers(self): return {name:hex(self.get(name)) for name in REGS}


class Probe:
    def __init__(self, path, sites, attach_pid=0):
        self.path=path; self.pe=PE(path); self.sites=sites; self.base=0
        self.pi=PROCESSINFO(); self.breakpoints={}; self.step_site={}; self.held=None
        self.threads={}; self.alive=False
        self.attach_pid=attach_pid
        self.variable_names={}
        self.numeric_edit_test=False
        self.numeric_edit_done=False
        self.adapter=None
        bridge=Path(__file__).parent/".cache/runner_adapter.dll"
        if bridge.exists():
            self.adapter=C.CDLL(str(bridge))
            self.read_callback_type=C.CFUNCTYPE(C.c_bool,PTR,U64,PTR,SIZE)
            def read_callback(owner,address,output,size):
                got=SIZE()
                return bool(K.ReadProcessMemory(self.pi.process,address,output,size,C.byref(got)) and got.value==size)
            self.read_callback=self.read_callback_type(read_callback)
            self.adapter.VerifySnapshot.argtypes=[self.read_callback_type,PTR,U64,U64,W.UINT,U64]
            self.adapter.VerifySnapshot.restype=W.UINT
    def read(self,address,size):
        if not address or size>1024*1024:raise ValueError("invalid probe read")
        buf=C.create_string_buffer(size); got=SIZE()
        checked(K.ReadProcessMemory(self.pi.process,address,buf,size,C.byref(got)),"ReadProcessMemory")
        if got.value!=size:raise ValueError("partial probe read")
        return buf.raw
    def qword(self,address): return struct.unpack("<Q",self.read(address,8))[0]
    def string(self,address,limit=256):
        if not address:return None
        result=bytearray()
        for i in range(limit):
            b=self.read(address+i,1)
            if b==b"\0":return result.decode("utf-8",errors="replace")
            result+=b
        return result.decode("utf-8",errors="replace")+"..."
    def write(self,address,data):
        old=W.DWORD(); size=len(data)
        checked(K.VirtualProtectEx(self.pi.process,address,size,0x40,C.byref(old)),"VirtualProtectEx")
        try:
            buf=C.create_string_buffer(data); done=SIZE()
            checked(K.WriteProcessMemory(self.pi.process,address,buf,size,C.byref(done)),"WriteProcessMemory")
            if done.value!=size:raise ValueError("partial probe write")
            checked(K.FlushInstructionCache(self.pi.process,address,size),"FlushInstructionCache")
        finally:
            ignored=W.DWORD(); checked(K.VirtualProtectEx(self.pi.process,address,size,old.value,C.byref(ignored)),"restore VirtualProtectEx")
    def launch(self):
        if self.attach_pid:
            self.pi.pid=self.attach_pid
            self.pi.process=K.OpenProcess(0x1fffff,False,self.attach_pid)
            checked(self.pi.process,"OpenProcess")
            checked(K.DebugActiveProcess(self.attach_pid),"DebugActiveProcess")
            checked(K.DebugSetProcessKillOnExit(False),"DebugSetProcessKillOnExit")
            self.alive=True
            return
        si=STARTUPINFO();si.cb=C.sizeof(si)
        cmd=C.create_unicode_buffer('"'+str(self.path)+'"')
        checked(K.CreateProcessW(str(self.path),cmd,None,None,False,2,None,str(self.path.parent),C.byref(si),C.byref(self.pi)),"CreateProcessW")
        self.alive=True;self.threads[self.pi.tid]=self.pi.thread
    def context(self,tid):
        if tid not in self.threads:
            h=K.OpenThread(0x1fffff,False,tid);checked(h,"OpenThread");self.threads[tid]=h
        return Context(self.threads[tid])
    def set_bp(self,address):
        if address not in self.breakpoints:self.breakpoints[address]=self.read(address,1)
        self.write(address,b"\xcc")
    def frame_snapshot(self,context):
        frame=context.get("rbx"); raw=self.read(frame,0xb0)
        q=lambda o:struct.unpack_from("<Q",raw,o)[0]
        u=lambda o:struct.unpack_from("<I",raw,o)[0]
        code=q(0x38); code_raw=self.read(code,0xb8)
        cq=lambda o:struct.unpack_from("<Q",code_raw,o)[0]
        cu=lambda o:struct.unpack_from("<I",code_raw,o)[0]
        result = {"frame":hex(frame),"parent":hex(q(8)),"child":hex(q(0)),"localObject":hex(q(0x20)),
                "self":hex(q(0x28)),"other":hex(q(0x30)),"code":hex(code),
                "codeName":self.string(cq(0x80)),"codeIndex":cu(0x88),"codeStartOffset":cu(0x9c),
                "argumentBase":hex(q(0x40)),"argumentCount":u(0x48),
                "bytecodeBase":hex(q(0x50)),"operandStackTop":hex(context.get("rdi")),
                "frameStackAnchor":hex(q(0x58)),"byteOffset":u(0x8c),"previousOffset":u(0x9c),
                "bytecodeLength":u(0x98),"nestedFrameDepth":u(0x94),
                "frameBytes":raw.hex(),"codeBytes":code_raw.hex()}
        result["anchorBytes"] = self.read(q(0x58),0x78).hex()
        if self.adapter:
            result["adapterFlags"]=self.adapter.VerifySnapshot(self.read_callback,None,self.base,frame,context.get("rcx")&0xffffffff,context.get("rdi"))
        for key, pointer in (("locals",q(0x20)),("instance",q(0x28))):
            if pointer:
                try:
                    obj=self.read(pointer,0x90)
                    result[key+"ObjectBytes"]=obj.hex()
                    values=struct.unpack_from('<Q',obj,8)[0]
                    count=struct.unpack_from('<I',obj,0x5c)[0]
                    if values and 0<count<=8192:
                        result[key+"ValuesBase"]=hex(values)
                        result[key+"Values"]=self.read(values,min(count,128)*16).hex()
                    map_address=struct.unpack_from('<Q',obj,0x48)[0]
                    if map_address:
                        map_raw=self.read(map_address,0x18)
                        capacity,used=struct.unpack_from('<II',map_raw)
                        entries=struct.unpack_from('<Q',map_raw,0x10)[0]
                        result[key+"Map"]={"address":hex(map_address),"capacity":capacity,"used":used,"entries":hex(entries)}
                        if 0<capacity<=32768 and 0<=used<=capacity:
                            found=[]
                            for off in range(0,capacity*16,16):
                                value,varid,hash_code=struct.unpack('<QIi',self.read(entries+off,16))
                                if hash_code>0 and value:
                                    if varid not in self.variable_names:
                                        name_count=struct.unpack('<I',self.read(self.base+0xa1d968,4))[0]
                                        names=self.qword(self.base+0xa1d970)
                                        self.variable_names[varid]=self.string(self.qword(names+(varid-100000)*8)) if 100000<=varid<100000+name_count else None
                                    found.append({"address":hex(value),"variableId":varid,"name":self.variable_names[varid],"hash":hash_code,"raw":self.read(value,16).hex()})
                                    if len(found)>=128:break
                            result[key+"Map"]["values"]=found
                            if self.numeric_edit_test and not self.numeric_edit_done and key=="locals":
                                for value in found:
                                    before=bytes.fromhex(value["raw"])
                                    if value["name"]=="_ResetJitter" and struct.unpack_from('<I',before,12)[0]==0:
                                        address=int(value["address"],16)
                                        replacement=struct.pack('<d',1.0)
                                        done=SIZE()
                                        try:
                                            checked(K.WriteProcessMemory(self.pi.process,address,C.create_string_buffer(replacement),8,C.byref(done)),"numeric test write")
                                            after=self.read(address,16)
                                            if done.value!=8 or after!=replacement+before[8:]:raise ValueError("numeric test readback differs")
                                            result["numericEditTest"]={"address":hex(address),"name":value["name"],"before":before.hex(),"after":after.hex()}
                                        finally:
                                            checked(K.WriteProcessMemory(self.pi.process,address,C.create_string_buffer(before[:8]),8,C.byref(done)),"numeric test restore")
                                            if self.read(address,16)!=before:raise ValueError("numeric test restore differs")
                                        result["numericEditTest"]["restored"]=True
                                        self.numeric_edit_done=True
                                        break
                except Exception as exc: result[key+"ReadError"]=str(exc)
        return result
    def run(self,max_stops,timeout):
        self.launch(); initial=True; captures=[]; deadline=time.monotonic()+timeout
        try:
            while self.alive and time.monotonic()<deadline and len(captures)<max_stops:
                event=C.create_string_buffer(176)
                if not K.WaitForDebugEvent(event,500):
                    if C.get_last_error()==121:continue
                    raise OSError(C.get_last_error(),"WaitForDebugEvent")
                raw=event.raw;kind,pid,tid=struct.unpack_from("<III",raw);self.held=(pid,tid)
                status=0x10002
                if kind==3:
                    self.base=struct.unpack_from("<Q",raw,40)[0]
                    print(json.dumps({"launchPid":pid,"base":hex(self.base),"sha256":self.pe.sha256}),flush=True)
                    file=struct.unpack_from("<Q",raw,16)[0]
                    if file:K.CloseHandle(file)
                elif kind==6:
                    file=struct.unpack_from("<Q",raw,16)[0]
                    if file:K.CloseHandle(file)
                elif kind==1:
                    code=struct.unpack_from("<I",raw,16)[0];addr=struct.unpack_from("<Q",raw,32)[0]
                    first=struct.unpack_from("<I",raw,168)[0]
                    if code==0x80000003 and initial:
                        initial=False
                        for rva in self.sites:self.set_bp(self.base+rva)
                    elif code==0x80000003 and addr in self.breakpoints:
                        context=self.context(tid);self.write(addr,self.breakpoints[addr]);context.set("rip",addr)
                        record={"stop":len(captures)+1,"tid":tid,"siteRva":hex(addr-self.base),"registers":context.registers()}
                        try:record["vm"]=self.frame_snapshot(context)
                        except Exception as exc:record["snapshotError"]=str(exc)
                        captures.append(record);print(json.dumps(record),flush=True)
                        if len(captures)<max_stops:
                            context.flags(context.flags()|0x100);self.step_site[tid]=addr
                        else:
                            for bp,original in self.breakpoints.items():self.write(bp,original)
                            context.flags(context.flags()&~0x100)
                        context.write(self.threads[tid])
                    elif code==0x80000004 and tid in self.step_site:
                        context=self.context(tid);context.flags(context.flags()&~0x100);context.write(self.threads[tid])
                        self.set_bp(self.step_site.pop(tid))
                    else:
                        status=0x80010001
                        if not first:print(json.dumps({"secondChance":hex(code),"address":hex(addr)}),flush=True)
                elif kind==5:
                    self.alive=False;print(json.dumps({"exitCode":struct.unpack_from('<I',raw,16)[0]}),flush=True)
                checked(K.ContinueDebugEvent(pid,tid,status),"ContinueDebugEvent");self.held=None
            return captures
        finally:
            # Newly created processes are test-owned. Attached processes are restored/detached.
            if self.alive and not self.attach_pid:K.TerminateProcess(self.pi.process,0)
            if self.alive and self.attach_pid:
                if not self.held:
                    checked(K.DebugBreakProcess(self.pi.process),"cleanup DebugBreakProcess")
                    event=C.create_string_buffer(176)
                    checked(K.WaitForDebugEvent(event,5000),"cleanup WaitForDebugEvent")
                    raw=event.raw;kind,pid,tid=struct.unpack_from("<III",raw);self.held=(pid,tid)
                    if kind==1 and struct.unpack_from('<I',raw,16)[0]==0x80000003:
                        addr=struct.unpack_from('<Q',raw,32)[0]
                        if addr in self.breakpoints:
                            c=self.context(tid);c.set('rip',addr);c.flags(c.flags()&~0x100);c.write(self.threads[tid])
                for bp,original in self.breakpoints.items():self.write(bp,original)
                for tid in self.step_site:
                    c=self.context(tid);c.flags(c.flags()&~0x100);c.write(self.threads[tid])
            if self.held:K.ContinueDebugEvent(*self.held,0x10002);self.held=None
            K.DebugActiveProcessStop(self.pi.pid)
            for h in set(self.threads.values()):K.CloseHandle(h)
            if self.pi.process:K.CloseHandle(self.pi.process)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stops",type=int,default=12)
    ap.add_argument("--timeout",type=float,default=30)
    ap.add_argument("--sites",nargs="+",type=lambda x:int(x,16),default=[0x285e16,0x28617e])
    ap.add_argument("--attach",type=int,default=0)
    ap.add_argument("--numeric-edit-test",action="store_true",help="Verify and immediately restore one known temporary numeric local under the same held stop")
    args=ap.parse_args()
    pe=PE(DEFAULT_EXE)
    if pe.sha256!="5664918ea125b0d1d763d51fe84ce10ef974dab8ded1014026ffda69fb433f1e":
        raise ValueError("The validated inspection target changed; refusing runtime breakpoints")
    probe=Probe(DEFAULT_EXE,args.sites,args.attach)
    probe.numeric_edit_test=args.numeric_edit_test
    probe.run(args.stops,args.timeout)


if __name__=="__main__":main()
