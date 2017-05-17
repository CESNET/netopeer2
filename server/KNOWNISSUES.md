Changes on sysrepo modules are not reflected
--------------------------------------------

If the libc implementation (e.g. musl) does not implement
pthread_rwlockattr_setkind_np() and the number of worker threads is increased
(via cmake THREAD_COUNT variable), the thread processing the modules changes in
sysrepo (module install/uninstall or feature changes) can starve by waiting
for lock to wite changes into the netopeer's context.
