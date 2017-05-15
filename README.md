# Puma
Puma is a Linux kernel module that enables a distributed page cache between multiple hosts. It relies on the existing cleancache API, but an updated Linux kernel is required to remove some limitations and improve its performance (see https://github.com/mlorrillere/linux-puma).

You need to pass the *enable* parameter to enable the module. Once loaded, you can add *remotes* by writing an *ip:port* string to the /sys/modules/remotecache/parameters/remotes file.
