#ifndef _LINUX_GPU_H
#define _LINUX_GPU_H

#include <linux/mm.h>
#include <linux/jump_label.h>

#ifdef CONFIG_GPU


extern int gpu_init(void);

#else

static inline int gpu_init(void) {printk("gpu cgroup empty!\n"); return 0; }

#endif /* !CONFIG_GPU */


#endif /* _LINUX_GPU_H */

