#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/export.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/backing-dev.h>
#include <linux/sort.h>

#include <asm/uaccess.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/cgroup.h>
#include <linux/wait.h>


static DEFINE_MUTEX(gpu_mutex);

struct gpu {
	struct cgroup_subsys_state css;
	u64 *gpuusage;
};

static inline struct gpu *css_cs(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct gpu, css) : NULL;
}

static inline struct gpu *task_cs(struct task_struct *task)
{
	return css_cs(task_css(task, gpu_cgrp_id));
}

static inline struct gpu *parent_cs(struct gpu *cs)
{
	return css_cs(cs->css.parent);
}

static struct dentry *gpu_mount(struct file_system_type *fs_type,
                int flags, const char *unused_dev_name, void *data)
{
	struct file_system_type *cgroup_fs = get_fs_type("cgroup");
	struct dentry *ret = ERR_PTR(-ENODEV);
	if (cgroup_fs) {
		char mountopts[] =
							"gpu,noprefix,"
							"release_agent=/sbin/gpu_release_agent";
		ret = cgroup_fs->mount(cgroup_fs, flags,
											unused_dev_name, mountopts);
		put_filesystem(cgroup_fs);
	}
	return ret;
}

static struct file_system_type gpu_fs_type = {
        .name = "gpu",
        .mount = gpu_mount,
};

typedef enum {
	GPU_STAT,
} gpu_filetype_t;

static int gpu_stats_show(struct seq_file *sf, void *v)
{
	return 50;
}

static struct cftype files[] = {
	{
		.name = "stat",
		.seq_show = gpu_stats_show,
	},

	{}
};

static struct cgroup_subsys_state *
gpu_css_alloc(struct cgroup_subsys_state *parent_css)
{
        struct gpu *cs;
        cs = kzalloc(sizeof(*cs), GFP_KERNEL);

        if (!cs)
                return ERR_PTR(-ENOMEM);

        return &cs->css;
}

static void gpu_css_free(struct cgroup_subsys_state *css)
{
        struct gpu *cs = css_cs(css);

        kfree(cs);
}

struct cgroup_subsys gpu_cgrp_subsys = {
	.css_alloc = gpu_css_alloc,
//	.css_online = gpu_css_online,
//	.css_offline = gpu_css_offline,
	.css_free = gpu_css_free,
//	.can_attach = gpu_can_attach,
//	.cancel_attach = gpu_cancel_attach,
//	.attach = gpu_attach,
//	.bind = gpu_bind,
	.legacy_cftypes = files,
	.early_init = 1,
};


int __init gpu_init(void)
{
	int err = 0;
	printk("gpu cgroup init\n");
  err = register_filesystem(&gpu_fs_type);
  if (err < 0)
		return err;

	return 0;
}

