obj-$(CONFIG_REMOTECACHE_MODULE) += remotecache.o
remotecache-y += node.o session.o stats.o messenger.o msgpool.o cache.o policy.o

obj-$(CONFIG_REMOTECACHE_POLICY_LRU) += remotecache-policy-lru.o
remotecache-policy-lru-y += policy-lru.o
