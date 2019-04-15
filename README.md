# so-checker
\
This is a small Python script to check for privilege escalation vulnerablities based on dynamically linked shared objects in Linux. It is based on this [blog post](https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library). It can be used by pentesters to quickly check a Linux system for this privilege escalation route or by system administrators to make sure their library paths don't have weak permissions.

\
Standard disclaimer: Use only against targets that you own or have permission to test.
