#ifndef __CLAT64_H__
#define __CLAT64_H__

#include <linux/in6.h>

struct clat46_config {
        struct in6_addr v6_prefix;
        struct in6_addr v6_addr;
        __u32 v4_addr;
};

#endif
