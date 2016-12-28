# nvram_patcher
Patches iOS kernel to allow access to all NVRAM variables.
This tool requires tfp0 kernel patch to work (I'm not quite sure if it works with host_get_special_port 4 workaround). If nvram_patcher doesn't work for you consider using nonceEnabler by tihmstar.
# Supported devices
I've tested it on iPad mini 4, iPad 4, iPod touch 4 and iPhone 5S, but it should work for all armv7 and arm64 devices.
# How it works
XNU uses a special table called gOFVariables to limit access to some critical NVRAM variables (e.g. boot-args) from userspace. This table contains access permissions and some other info about common variables used by OS X and iOS. This tool locates the gOFVariables table inside the kernel and patches permissions for each NVRAM varible that is only accessible to kernel to make them available with root permissions.
# Usage
Run nvram_patcher on the target device with root privileges.
# What if my device panics when running nvram_patcher?
That usually means that tfp0 kernel patch wasn't applied properly. Just retry several times.
# Build
make
# Thanks
Samuel Groß for ios-kern-utils

tihmstar for the idea
