# Outline
- Introduction
    - Feature
- Install
- Usage
- Documention
- Update log
# Introduction
python auto lib(based on `x64dbg`, add some functions)

## Features

# Install
You need to install x64dbg first.

patch x64dbg.exe and x32dbg.exe with the binary in release dir

edit rdbg.conf, set ip,port,use

git clone https://github.com/pxx199181/PyWinDbg/


`python setup.py install`
# Usage
## Basic

```python
import time
from PyWinDbg import PyWinDbg

def test64():
	pydbg = PyWinDbg("x64dbg.exe", ip = "127.0.0.1", port = 8881, bits = 64)
	
	pydbg.start()
	def hook_handler(pydbg):
		ip = pydbg.get_reg("pc")
		rdi = pydbg.get_reg("cdi")
		data = pydbg.read_mem(rdi, 0x20)
		print("test ip:", hex(ip), data)

	printf = pydbg.dbg_eval("printf")
	print("printf:", hex(printf))
	#raw_input(":")
	pydbg.hook(printf, hook_handler)

	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("si:")
	pydbg.si()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("ip:")
	print("ip:", hex(ip))
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("asm:")
	#pydbg.patch_asm(ip, "mov dword ptr ss:[esp-0x4], 0x12345678")
	raw_input("asm:")
	pydbg.patch_asm(ip, "push rax\npush rbx")
	raw_input("asm:")
	data = pydbg.disasm(ip)
	print("disasm:data:", data)

	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("si:")
	pydbg.si()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("undo:")
	pydbg.instrUndo()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("undo:")
	pydbg.instrUndo()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input(":")

	pydbg.enable_gui()
	#pydbg.start_trace("test.log")
	pydbg.set_traceLogFile("ins.log")
	pydbg.set_traceLogInfo(log = "\"eax:{p:eax}, ebx:{p:eax}\"", condition = "ebx == 0x0")
	pydbg.trace_StepInto(condition = "eax==0x80")
	#pydbg.stop_trace()
	raw_input("trace over:")
	raw_input("wait:")

	while True:
		#pydbg.so()
		#"""
		ip = pydbg.get_reg("pc")
		print("ip:", hex(ip))
		ip = pydbg.get_reg("pc")
		print("ip:", hex(ip))
		sign = pydbg.isRunning()
		print("sign:", sign)

		#pydbg.set_bp(ip + 0x5)
		pc = pydbg.Continue()
		if pc == -1:
			raw_input("hold on")
		#pydbg.run_until(ip + 0x92 - 0x73)

		addr = pydbg.get_base("x64dbg.exe")
		print("base:", hex(addr))

		sp = pydbg.get_reg("esp")
		data = pydbg.read_mem(sp, 0x20)
		print("data:", data.encode("hex"))

		#pydbg.write_mem(sp, "deadbeef")
		#cmd = raw_input("cmd:").strip()
		#pydbg.write_mem(sp, data)
		#"""

def test32():

	pydbg = PyWinDbg("x32dbg.exe", ip = "127.0.0.1", port = 8881, bits = 32)
	
	pydbg.start()
	#pydbg.disable_gui()
	#pydbg.pause()

	def hook_handler(pydbg):
		ip = pydbg.get_reg("pc")
		rdi = pydbg.get_reg("cdi")
		data = pydbg.read_mem(rdi, 0x20)
		print("test ip:", hex(ip), data)

	printf = pydbg.dbg_eval("printf")
	print("printf:", hex(printf))
	#raw_input(":")
	pydbg.hook(printf, hook_handler)

	#raw_input(":")
	#pydbg.si()
	#raw_input(":")
	#ip = pydbg.get_reg("EIP")
	#pydbg.run_until(ip + 0x92 - 0x73)
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("si:")
	pydbg.si()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("ip:")
	print("ip:", hex(ip))
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("asm:")
	#pydbg.patch_asm(ip, "mov dword ptr ss:[esp-0x4], 0x12345678")
	#raw_input("asm:")
	#pydbg.patch_asm(ip, "push rax\npush rbx")
	#raw_input("asm:")
	data = pydbg.disasm(ip)
	print("disasm:data:", data)

	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("si:")
	pydbg.si()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("undo:")
	pydbg.instrUndo()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input("undo:")
	pydbg.instrUndo()
	ip = pydbg.get_reg("pc")
	print("ip:", hex(ip))
	raw_input(":")

	pydbg.enable_gui()
	#pydbg.start_trace("test.log")
	pydbg.set_traceLogFile("ins.log")
	pydbg.set_traceLogInfo(log = "\"eax:{p:eax}, ebx:{p:eax}\"", condition = "ebx == 0x0")
	pydbg.trace_StepInto(condition = "eax==0x80")
	#pydbg.stop_trace()
	raw_input("trace over:")
	raw_input("wait:")

	while True:
		#pydbg.so()
		#"""
		ip = pydbg.get_reg("pc")
		print("ip:", hex(ip))
		ip = pydbg.get_reg("pc")
		print("ip:", hex(ip))
		sign = pydbg.isRunning()
		print("sign:", sign)

		#pydbg.set_bp(ip + 0x5)
		pc = pydbg.Continue()
		if pc == -1:
			raw_input("hold on")
		#pydbg.run_until(ip + 0x92 - 0x73)

		addr = pydbg.get_base("x32dbg.exe")
		print("base:", hex(addr))

		sp = pydbg.get_reg("esp")
		data = pydbg.read_mem(sp, 0x20)
		print("data:", data.encode("hex"))

		#pydbg.write_mem(sp, "deadbeef")
		#cmd = raw_input("cmd:").strip()
		#pydbg.write_mem(sp, data)
		#"""
	
if __name__ == "__main__":
	#test64()
	test32()
```

## More
read the code!

# Documention
TODO

# Update Log 
## 2022/4/27 Version 1.0.0
- (1). release it
