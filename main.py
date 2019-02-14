import subprocess
import os
import re

print('SO Checker')
print('Checking for vulnerable binaries')

setuid_binaries = {}
# implement logic to find setuid binaries and binaries started by root as cronjob
bin_paths = ['/bin', '/sbin', '/usr/bin']

for bin_path in bin_paths:
    for root,dirs,files in os.walk(bin_path):
        for binary in files:
            try:
                permissions = os.stat(os.path.join(root, binary))
                if oct(permissions[0])[3] == '4':
                    setuid_binaries[os.path.join(root, binary)] = 0
            except:
                pass

print(setuid_binaries)

for binary in setuid_binaries:
    # Check if binary uses shared library
    setuid_binaries[binary] = ['/lib', '/usr/lib']
    shared_libs = []
    output_raw = subprocess.Popen(['ldd', binary], stdout=subprocess.PIPE).communicate()
    regex = r"[^\\t ]/?[a-z0-9-_]*/?[a-z0-9-_]*/?[a-z0-9-_]+\.[a-z0-9-_]+[a-zA-Z0-9-_\.]+"
    matches = re.finditer(regex, str(output_raw))
    for match in matches:
        shared_libs.append(match.group())
    print('{} shared libraries found.'.format(len(shared_libs))) 

    if shared_libs:
        # Check for RPATH and DT_RUNPATH linker options
        output_raw = subprocess.Popen(['objdump', '-x', binary], stdout=subprocess.PIPE).communicate()
        for item in output_raw[0].split('\n'):
            if 'RPATH' in item:
                setuid_binaries[binary].append(item.strip().split()[1])
            if 'RUNPATH' in item:
                setuid_binaries[binary].append(item.strip().split()[1])
        
        # Check for environment variables
        if 'LD_RUN_PATH' in os.environ:
            setuid_binaries[binary].append(os.environ.get('LD_RUN_PATH'))
        if 'LD_LIBRARY_PATH' in os.environ:
            setuid_binaries[binary].append(os.environ.get('LD_LIBRARY_PATH'))

        # Check ld.so.conf
        # TBD

# print(lib_paths)
for binary in setuid_binaries:
    for lib_path in setuid_binaries[binary]:
        if os.access(lib_path, os.W_OK):
            print(binary + ' is vulnerable:')
            print(lib_path + ' is writable!')
            print
