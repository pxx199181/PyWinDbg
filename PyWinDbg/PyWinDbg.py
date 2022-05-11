import struct
import socket
import telnetlib
import time

def readuntil(f, delim=': '):
    data = ''
    while not data.endswith(delim):
        data += f.read(1)
    return data

def p64(v):
    return struct.pack('<Q', v)

def u64(v):
    return struct.unpack('<Q', v)[0]

def p32(v):
    return struct.pack('<I', v)

def u32(v):
    return struct.unpack('<I', v)[0]

def p16(v):
    return struct.pack('<H', v)

def u16(v):
    return struct.unpack('<H', v)[0]

def get_io(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	io = s.makefile('rw', bufsize=0)
	return io, s

def interact(s):
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()


RDBG_QUIT = 0
RDBG_KILL = 1
RDBG_READ = 2
RDBG_WRITE = 3
RDBG_CMD  = 4
RDBG_SMSG = 5
RDBG_OK = 6
RDBG_ERROR = 7

RDBG_ISRUNING 	= 8
RDBG_EVAL 		= 9
RDBG_VALTOSTR	= 10
RDBG_REG_W		= 11
RDBG_REG_R		= 12

RDBG_DISASM		= 13
RDBG_ASM 		= 14

RDBG_MODULEBASE = 15
RDBG_WAITPAUSE = 16

RDBG_CMD_DIRECT = 17

class PyWinDbg():
	"""docstring for PyWinDbg"""
	def __init__(self, target = "", cmdline = "", ip = "127.0.0.1", port = 8888, bits = 32):
		self.target = target
		self.cmdline = cmdline
		self.bits = bits

		if bits == 32:
			self.p_ptr = p32
			self.u_ptr = u32
			self.ptr_size = 4
		else:
			self.p_ptr = p64
			self.u_ptr = u64
			self.ptr_size = 8

		self.reg_maps = {}
		if bits == 32:
			self.pc = "eip"
			self.sp = "esp"
		else:
			self.pc = "rip"
			self.sp = "rsp"
		self.reg_maps["pc"] = self.pc
		self.reg_maps["sp"] = self.sp

		io, s = get_io(ip, port)
		self.debugger = io
		self.debugger_s = s

		self.hook_maps = {}
		self.globals = {}

	def send(self, *arg, **kwds):
		return self.debugger.write(*arg, **kwds)

	def recv(self, *arg, **kwds):
		return self.debugger.read(*arg, **kwds)

	def recvSize(self, size):
		data = ""
		while len(data) < size:
			data += self.recv(size - len(data))
		return data

	def send_sign_pkt(self, sign, data = None):
		self.send(chr(sign))
		if data is not None:
			size = len(data)
			self.send(p32(size))
			self.send(data)
		else:
			size = 0
			self.send(p32(size))

	def recv_sign_pkt(self):
		sign = self.recvSize(1)
		data = self.recvSize(4)
		size = u32(data)
		if size > 0:
			data = self.recvSize(size)
		else:
			data = None
		return ord(sign), data, size

	def read_mem(self, addr, size):
		self.send_sign_pkt(RDBG_READ, self.p_ptr(addr) + p32(size))
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			return data
		return ""

	def write_mem(self, addr, data):
		self.send_sign_pkt(RDBG_WRITE, self.p_ptr(addr) + data)
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			return True
		return False


	def dbg_exec(self, cmd):
		self.send_sign_pkt(RDBG_CMD, cmd + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			sign = ord(data)
			return sign
		return False

	def dbg_exec_direct(self, cmd):
		self.send_sign_pkt(RDBG_CMD_DIRECT, cmd + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			sign = ord(data)
			return sign
		return False

	def dbg_smsg(self, info):
		self.send_sign_pkt(RDBG_SMSG, info + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			print("data:", data)
			return sign
		return False

	def start(self, target = None, cmdline = None):
		if target is not None:
			self.target = target
			self.cmdline = ""
		if cmdline is not None:
			self.cmdline = cmdline
		self.dbg_exec_direct("init %s,%s"%(self.target, self.cmdline))
		self.waitPause()

	def dbg_eval(self, name):
		self.send_sign_pkt(RDBG_EVAL, name + "\x00")
		sign, data, size = self.recv_sign_pkt()
		#print(sign, data, size)
		if sign == RDBG_OK:
			#print("0")
			return self.u_ptr(data)
		else:
			#print("1")
			return None

	def dbg_valToStr(self, name, value):
		self.send_sign_pkt(RDBG_VALTOSTR, self.p_ptr(value), name + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			return True
		else:
			return False

	def get_reg(self, reg):
		reg = reg.lower()
		if reg in self.reg_maps.keys():
			reg = self.reg_maps[reg]
		return self.dbg_eval(reg)

	def set_reg(self, reg, value):
		reg = reg.lower()
		if reg in self.reg_maps.keys():
			reg = self.reg_maps[reg]
		return self.dbg_valToStr(reg, value)

	def get_base(self, name):
		self.send_sign_pkt(RDBG_MODULEBASE, name + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			return self.u_ptr(data)
		else:
			return None

	def isRunning(self):
		self.send_sign_pkt(RDBG_ISRUNING)
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			return ord(data)
		else:
			return None

	def attach(self, pid):
		return self.dbg_exec_direct("attach %d"%pid)

	def stop(self):
		return self.dbg_exec_direct("stop")

	def pause(self):
		return self.dbg_exec_direct("pause")

	def stepInto(self, count = None):
		cmdline = "StepInto"
		if count is not None:
			cmdline += ", %d"%count
		return self.dbg_exec_direct(cmdline)

	def stepOver(self, count = None):
		cmdline = "StepOver"
		if count is not None:
			cmdline += ", %d"%count
		return self.dbg_exec_direct(cmdline)

	def stepOut(self, count = None):
		cmdline = "StepOut"
		if count is not None:
			cmdline += ", %d"%count
		return self.dbg_exec_direct(cmdline)

	def waitPause(self, sleepTime = 0.3, hold = False):
		#time.sleep(0.3)
		if hold == True:
			self.send_sign_pkt(RDBG_WAITPAUSE)
			sign, data, size = self.recv_sign_pkt()
			if sign == RDBG_ERROR:
				return False
		else:
			while self.isRunning():
				time.sleep(sleepTime)
		return True

	def safeWaitPause(self, sleepTime = 0.3, hold = False):
		try:
			self.waitPause(sleepTime = sleepTime, hold = hold)
		except KeyboardInterrupt:
			print('[+] ' + 'Interrupted')
			if hold == False:
				self.pause()

	def dealHook(self):
		pc = self.get_reg("pc")
		
		if pc in self.hook_maps.keys():
			[handler, bpType, args] = self.hook_maps[pc]
			new_args = [self] + list(args)
			if handler(*new_args) == False:
				return False, pc
		else:
			return False, pc
		return True, pc

	def Continue(self, hold = False):
		while True:
			try:
				self.dbg_exec_direct("go")
				self.waitPause(hold = hold)
				sign, pc = self.dealHook()
				if sign == False:
					return pc
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				if hold == False:
					self.pause()
					return -1

	def run_until(self, addr, hold = False):
		self.set_bp(addr)
		while True:
			try:
				self.dbg_exec_direct("go")
				self.waitPause(hold = hold)
				sign, pc = self.dealHook()
				#print(hex(pc), hex(addr))
				if pc == addr:
					break
			except KeyboardInterrupt:
				print('[+] ' + 'Interrupted')
				if hold == False:
					self.pause()
					pc = -1
					break
		self.del_bp(addr)
		return pc

	def patch_asm_size(self, addr, code):
		self.send_sign_pkt(RDBG_ASM, self.p_ptr(addr) + code + "\x00")
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			#print("data", repr(data))
			sign = ord(data)
			return sign
		else:
			return False

	def patch_asm(self, addr, code, nop_pad = True):
		if ";" in code:
			code = code.replace(";", "\n")
		code = code.strip()
		code_list = code.split("\n")
		for idx, each_code in enumerate(code_list):
			cmdline = "asm 0x%x,\"%s\""%(addr, each_code)
			if nop_pad == True:
				cmdline += ",1"
			res = self.dbg_exec_direct(cmdline)
			if idx < len(code_list) - 1:
				code_asm, code_size = self.disasm(addr)
				if code_size == 0:
					return False
				addr += code_size
		return res

	def disasm(self, addr):
		self.send_sign_pkt(RDBG_DISASM, self.p_ptr(addr))
		sign, data, size = self.recv_sign_pkt()
		if sign == RDBG_OK:
			#import hexdump
			#hexdump.hexdump(data)
			instr_size = u32(data[64+8:64+0xc])
			pos = data.find("\x00")
			data = data[:pos]
			return data, instr_size
		else:
			return None, 0

	def si(self, count = None):
		return self.stepInto(count = count)

	def so(self, count = None):
		return self.stepOver(count = count)

	def go(self):
		return self.Continue()

	def interact_pydbg(self):
		while True:
			data = raw_input("cmd:").strip()
			if data.startswith("q") or data.startswith("exit"):
				break
			self.dbg_exec_direct(data)

	def set_bp(self, addr, hard = False):
		if hard == True:
			cmd = "bph"
		else:
			cmd = "bp"

		return self.dbg_exec_direct("%s 0x%x"%(cmd, addr))

	def del_bp(self, addr = None, hard = False):
		if hard == True:
			cmd = "bphc"
		else:
			cmd = "bpc"

		if addr == None:
			addr_str = ""
		else:
			addr_str = "0x%x"%addr
		return self.dbg_exec_direct("%s %s"%(cmd, addr_str))

	def set_mem_bp(self, addr):
		cmd = "bpm"

		return self.dbg_exec_direct("%s 0x%x"%(cmd, addr))

	def del_mem_bp(self, addr = None):
		cmd = "bpmc"

		if addr == None:
			addr_str = ""
		else:
			addr_str = "0x%x"%addr
		return self.dbg_exec_direct("%s %s"%(cmd, addr_str))

	def hook(self, addr, handler, args = [], bpType = "normal"):
		if bpType == "mem":
			self.set_mem_bp(addr)
		elif bpType == "hard":
			self.set_bp(addr, hard = True)
		else:
			self.set_bp(addr)

		self.hook_maps[addr] = [handler, bpType, args]

	def remove_hook(self, addr):
		if addr in self.hook_maps.keys():
			[handler, bpType, args] = self.hook_maps[addr]
			self.hook_maps.pop(addr)
			if bpType == "mem":
				self.del_mem_bp(addr)
			elif bpType == "hard":
				self.del_bp(addr, hard = True)
			else:
				self.del_bp(addr)

	def detach(self):
		return self.dbg_exec_direct("detach")

	def instrUndo(self):
		return self.dbg_exec_direct("InstrUndo")

	def load_lib(self, libname):
		return self.dbg_exec_direct("loadlib %s"%libname)

	def unload_lib(self, libname):
		return self.dbg_exec_direct("freelib %s"%libname)

	def chdir(self, dirname):
		return self.dbg_exec_direct("chdir %s"%dirname)

	def enable_gui(self):
		return self.dbg_exec_direct("guiupdateenable")

	def disable_gui(self):
		return self.dbg_exec_direct("guiupdatedisable")

	def start_trace(self, logfile = "trace.log"):
		return self.dbg_exec_direct("opentrace %s"%logfile)

	def stop_trace(self):
		return self.dbg_exec_direct("StopRunTrace")

	def set_traceLogFile(self, logfile = "trace.log"):
		return self.dbg_exec_direct("SetTraceLogFile %s"%logfile)

	def set_traceLogInfo(self, log = "0x{p:cip}", condition = "eax==0"):
		return self.dbg_exec_direct("SetTraceLog %s,%s"%(log, condition))

	def trace_StepInto(self, condition = '0', count = 50000, hold = False, logfile = None):
		if logfile is not None:
			set_traceLogFile(logfile)
		self.dbg_exec_direct("TraceIntoConditional %s,%d"%(condition, count))
		self.safeWaitPause(hold = hold)

	def trace_StepOver(self, condition = '0', count = 50000, hold = False, logfile = None):
		if logfile is not None:
			set_traceLogFile(logfile)
		self.dbg_exec_direct("TraceOverConditional %s,%d"%(condition, count))
		self.safeWaitPause(hold = hold)
