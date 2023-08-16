import subprocess 

script1 = "policy_vulngrp_warn.py"
script2 = "policy_vulngrp_block.py"

print("\n##### Master Policy Vulnerability Group Script for Block and Report #####")
# print("\nExecuting policy_vulngrp_warn:", script1)
# subprocess.run(["python", script1])

print("\nExecuting policy_vulngrp_block:", script2)  
subprocess.run(["python3", script2])