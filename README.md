# WSA-Kernel-SU

## Intro

This is a kernel module to provide `/system/xbin/su` to Android Kernel (especially to WSA).

Only works on 4.17+ kernel. For older kernel, you can refer to the [origin repo](https://git.zx2c4.com/kernel-assisted-superuser).

## How it works
- Replace syscall `newfstatat`, `faccessat` and `execve` on `/system/xbin/su` to `/system/bin/sh`
- When `execve` on `/system/xbin/su`, change SELinux to permissive, set all kinds of uids and gids to 0 and permit all capabilities.

## Improvement
- Instead of setting SELinux to permissive, we should set the target process to a permissive context
- Instead of allowing all to access and execute `/system/xbin/su`, we should allow only permitive uid or gid.

## License
GPLv2

## Credits
Jason A. Donenfeld for the original implementation
