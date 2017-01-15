#!/usr/bin/env python

"""
This script is called by roptester.c to update the
base addresses of exploit.py generated by ropbuilder.py.
"""

import os
import sys
import subprocess

def get_base_addr(pid, dlls):
	ps_maps_path = "/proc/%d/maps" % pid
	ps_map = [line.rstrip("\n").split() for line in open(ps_maps_path)]
	
	print ""
	print "[*] cat %s" % ps_maps_path
	print ("\n".join([line.rstrip("\n") for line in open(ps_maps_path)]))
	print ""

	# follow symbolic links
	dlls = [os.path.realpath(dll) for dll in dlls]
	return ["0x" + lib[0].split("-")[0] for dll in dlls for lib in ps_map if lib[-1] == dll and lib[1] == "r-xp"]

def rebase_exploit_py(exploit_py, bases):
	with open(exploit_py, "r+") as f:
		lines = f.readlines()
		rebased_lines = []
		for line in lines:
			for (base_index, base) in enumerate(bases):
				image_base_str = "IMAGE_BASE_%d = " % base_index
				found_at = line.find(image_base_str)
				if found_at != -1:
					found_at += len(image_base_str)
					line = line[:found_at] + base + line[found_at + len(base):]
					print ("[*] Rebased line: %s" % line).rstrip("\n")
			rebased_lines.append(line)
		f.seek(0)
		f.writelines(rebased_lines)
		f.close()

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print "Insufficient arguments"
		print "Usage: python %s <pid> <lib-1> <lib-2> ... <exploit.py>" % sys.argv[0]
		print "Description: rebase <lib-[i]> base offsets in <exploit.py> according to process maps of <pid>"
		sys.exit(-1)

	pid = int(sys.argv[1])
	exploit_py = sys.argv[2]
	dlls = sys.argv[3:]

	bases = get_base_addr(pid, dlls)
	rebase_exploit_py(exploit_py, bases)

	print "[*] Generating payload.out"
	subprocess.call("python " + exploit_py, shell=True)

