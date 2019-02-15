import subprocess
import os
import re
import stat

print('----- SO Checker -----')
print('Checking for vulnerable binaries')
print()

setuid_binaries = {}
vulnerable = False
bin_paths = ['/home/', '/bin', '/sbin', '/usr/bin', '/opt', '/root']

# Search for setuid binaries
for bin_path in bin_paths:
    for root,dirs,files in os.walk(bin_path):
        for binary in files:
            try:
                if os.stat(os.path.join(root, binary)).st_mode & stat.S_ISUID == 2048:
                    setuid_binaries[os.path.join(root, binary)] = 0
            except:
                pass

for binary in setuid_binaries:
    # Check if binary uses shared libraries
    setuid_binaries[binary] = ['/lib', '/usr/lib']
    shared_libs = []
    output_raw = subprocess.Popen(['ldd', binary], stdout=subprocess.PIPE).communicate()
    regex = r"[^\\t ]/?[a-z0-9-_]*/?[a-z0-9-_]*/?[a-z0-9-_]+\.[a-z0-9-_]+[a-zA-Z0-9-_\.]+"
    matches = re.finditer(regex, str(output_raw))

    for match in matches:
        shared_libs.append(match.group())

    if shared_libs:
        # Check for RPATH and DT_RUNPATH linker options
        output_raw = subprocess.Popen(['objdump', '-x', binary], stdout=subprocess.PIPE).communicate()
        for item in output_raw[0].decode().split('\n'):

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

for binary in setuid_binaries:
    for lib_path in setuid_binaries[binary]:

        if os.access(lib_path, os.W_OK):
            print('{} is vulnerable:'.format(binary))
            print('{} is writable'.format(lib_path))
            vulnerable = True

if vulnerable == False:
    print('No vulnerable binaries found.')
