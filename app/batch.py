import os
import subprocess

benchmarks = ["bftpd", "git", "gzip", "httpd", "libcurl", "lmdb", "sqlite",
              "401.bzip2", "403.gcc", "429.mcf", "433.milc", "444.namd", "445.gobmk",
	      "456.hmmer", "458.sjeng","462.libquantum", "470.lbm", "482.sphinx"]
#benchmarks = ["git", "gzip", "httpd"]


for benchmark in benchmarks:
	# Set 1 - O3 gcc
	command_control = "./etharden -m ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_gcc_orig_O3 ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_gcc_control_O3"
	command_xform = "./etharden -m --gadget-reduction ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_gcc_orig_O3 ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_gcc_transformed_O3"


	sub = subprocess.Popen(command_control, shell=True, stdout=subprocess.PIPE)
	subprocess_return = sub.stdout.read()
	print(subprocess_return)

	sub = subprocess.Popen(command_xform, shell=True, stdout=subprocess.PIPE)
	subprocess_return = sub.stdout.read()
	print(subprocess_return)

	# Set 2 - O3 clang
	command_control = "./etharden -m ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_clang_orig_O3 ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_clang_control_O3"
	command_xform = "./etharden -m --gadget-reduction ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_clang_orig_O3 ~/cs8903/transformed/" + benchmark + "/O3/" + benchmark + "_clang_transformed_O3"


	sub = subprocess.Popen(command_control, shell=True, stdout=subprocess.PIPE)
	subprocess_return = sub.stdout.read()
	print(subprocess_return)

	sub = subprocess.Popen(command_xform, shell=True, stdout=subprocess.PIPE)
	subprocess_return = sub.stdout.read()
	print(subprocess_return)

	# Set 3 - OFP (gcc)
	#command_control = "./etharden -m ~/cs8903/transformed/" + benchmark + "/omit-fp/" + benchmark + "_gcc_orig_ofp ~/cs8903/transformed/" + benchmark + "/omit-fp/" + benchmark + "_gcc_control_ofp"
	#command_xform = "./etharden -m --gadget-reduction ~/cs8903/transformed/" + benchmark + "/omit-fp/" + benchmark + "_gcc_orig_ofp ~/cs8903/transformed/" + benchmark + "/omit-fp/" + benchmark + "_gcc_transformed_ofp"


	#sub = subprocess.Popen(command_control, shell=True, stdout=subprocess.PIPE)
	#subprocess_return = sub.stdout.read()
	#print(subprocess_return)

	#sub = subprocess.Popen(command_xform, shell=True, stdout=subprocess.PIPE)
	#subprocess_return = sub.stdout.read()
	#print(subprocess_return)


