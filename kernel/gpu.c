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

// This needs to be written in Kconfig.
#define NR_GPUS 1024

static DEFINE_MUTEX(gpu_mutex);
static DEFINE_SPINLOCK(callback_lock);

struct gpu {
	struct cgroup_subsys_state css;
	unsigned long flags;
	int relax_domain_level;
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

typedef enum {
	CS_ONLINE,
	CS_GPU_EXCLUSIVE,
	CS_SCHED_LOAD_BALANCE,
} gpu_flagbits_t;

static inline bool is_gpu_online(const struct gpu *cs)
{
	return test_bit(CS_ONLINE, &cs->flags);
}

static inline int is_gpu_exclusive(const struct gpu *cs)
{
	return test_bit(CS_GPU_EXCLUSIVE, &cs->flags);
}

static inline is_sched_load_balance(const struct gpu *cs)
{
	return test_bit(CS_SCHED_LOAD_BALANCE, &cs->flags);
}

static struct dentry *gpu_mount(struct file_system_type *fs_type,
                int flags, const char *unused_dev_name, void *data)
{
        struct file_system_type *cgroup_fs = get_fs_type("cgroup");
        struct dentry *ret = ERR_PTR(-ENODEV);
        if (cgroup_fs) {
                char mountopts[] =
                        "gpu,"
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
	FILE_GPULIST,
	FILE_EFFECTIVE_GPULIST,
	FILE_GPU_EXCLUSIVE,
	FILE_GPU_EFFECTIVE,
	FILE_SCHED_LOAD_BALANCE,
	FILE_SCHED_RELAX_DOMAIN_LEVEL,
} gpu_filetype_t;

static int gpu_write_u64(struct cgroup_subsys_state *css, struct cftype *cft,
					u64 val)
{
	struct gpu *cs = css_cs(css);
	gpu_filetype_t type = cft->private;
	int retval = 0;

	mutex_lock(&gpu_mutex);
	if (!is_gpu_online(cs)) {
		retval = -ENODEV;
		goto out_unlock;
	}

	switch (type) {
	case FILE_GPULIST:
		// retval = ...
		break;
	case FILE_EFFECTIVE_GPULIST:
		// retval = ...
		break;
	case FILE_GPU_EFFECTIVE:
		// retval = ...
		break;
	case FILE_SCHED_LOAD_BALANCE:
		// retval = ...
		break;
	case FILE_SCHED_RELAX_DOMAIN_LEVEL:
		// retval = ...
		break;
	default:
		retval = -EINVAL;
	}
out_unlock:
	mutex_unlock(&gpu_mutex);
	return retval;
}

static int gpu_write_s64(struct cgroup_subsys_state *css, struct cftype *cft,
				s64 val)
{
	struct gpu *cs = css_cs(css);
	gpu_filetype_t type = cft->private;
	int retval = -ENODEV;

	mutex_lock(&gpu_mutex);
	if (!is_gpu_online(cs))
		goto out_unlock;

	switch (type) {
	case FILE_SCHED_RELAX_DOMAIN_LEVEL:
		// retval = ...
		break;
	default:
		retval = -EINVAL;
		break;
	}
out_unlock:
	mutex_unlock(&gpu_mutex);
	return retval;
}

static ssize_t gpu_write_resmask(struct kernfs_open_file *of,
						char *buf, size_t nbytes, loff_t off)
{
	struct gpu *cs = css_cs(of_css(of));
	struct gpu *trialcs;
	int retval = -ENODEV;

	buf = strstrip(buf);

	css_get(&cs->css);
	// kernfs_break_active_protection(of->kn);

	mutex_lock(&gpu_mutex);
	if (!is_gpu_online(cs))
		goto out_unlock;
/*
	trialcs = alloc_trial_gpu(cs);
	if (!trialcs) {
		retval = -ENOMEM;
		goto out_unlock;
	}
*/
	switch (of_cft(of)->private) {
	case FILE_GPULIST:
		// retval = update_cpumask(cs, trialcs, buf);
		break;
	default:
		retval = -EINVAL;
		break;
	}

//	free_trial_gpu(trialcs);
out_unlock:
	mutex_unlock(&gpu_mutex);
	css_put(&cs->css);
	return retval ?: nbytes;
}

static int gpu_common_seq_show(struct seq_file *sf, void *v)
{
	struct gpu *cs = css_cs(seq_css(sf));
	gpu_filetype_t type = seq_cft(sf)->private;
	int ret = 0;

	spin_lock_irq(&callback_lock);

	switch (type) {
	case FILE_GPULIST:
		// seq_printf(sf, "%*pbl\n", ...);
		break;
	case FILE_EFFECTIVE_GPULIST:
		// seq_printf(sf, "%*pbl\n", ...);
		break;
	default:
		ret = -EINVAL;
	}

	spin_unlock_irq(&callback_lock);
	return ret;
}


static u64 gpu_read_u64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct gpu *cs = css_cs(css);
	gpu_filetype_t type = cft->private;
	switch (type) {
	case FILE_GPU_EXCLUSIVE:
		return is_gpu_exclusive(cs);
	case FILE_SCHED_LOAD_BALANCE:
		return is_sched_load_balance(cs);
	default:
		BUG();
	}

	return 0;
}

static s64 gpu_read_s64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct gpu *cs = css_cs(css);
	gpu_filetype_t type = cft->private;
	switch (type) {
	case FILE_SCHED_RELAX_DOMAIN_LEVEL:
		return cs->relax_domain_level;
	default:
		BUG();
	}

	return 0;
}

static struct cftype files[] = {
	{
		.name = "gpus",
		.seq_show = gpu_common_seq_show,
		.write = gpu_write_resmask,
		.max_write_len = (100U + 6 * NR_GPUS),
		.private = FILE_GPULIST,	
	},

	{
		.name = "effective_gpus",
		.seq_show = gpu_common_seq_show,
		.private = FILE_EFFECTIVE_GPULIST,
	},

	{
		.name = "gpu_exclusive",
		.read_u64 = gpu_read_u64,
		.write_u64 = gpu_write_u64,
		.private = FILE_GPU_EXCLUSIVE,
	},

	{
		.name = "sched_load_balance",
		.read_u64 = gpu_read_u64,
		.write_u64 = gpu_write_u64,
		.private = FILE_SCHED_LOAD_BALANCE,
	},

	{
		.name = "sched_relax_domain_level",
		.read_s64 = gpu_read_s64,
		.write_u64 = gpu_write_s64,
		.private = FILE_SCHED_RELAX_DOMAIN_LEVEL,
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

static int gpu_css_online(struct cgroup_subsys_state *css)
{
	struct gpu *cs = css_cs(css);
	struct gpu *parent = parent_cs(cs);
	struct gpu *tmp_cs;
	struct cgroup_subsys_state *pos_css;

	if (!parent)
		return 0;

	mutex_lock(&gpu_mutex);

	mutex_unlock(&gpu_mutex);
	return 0;
}

static void gpu_css_offline(struct cgroup_subsys_state *css)
{
	struct gpu *cs = css_cs(css);

	mutex_lock(&gpu_mutex);

	mutex_unlock(&gpu_mutex);
}

static void gpu_css_free(struct cgroup_subsys_state *css)
{
        struct gpu *cs = css_cs(css);

        kfree(cs);
}

static void gpu_bind(struct cgroup_subsys_state *root_css)
{
	mutex_lock(&gpu_mutex);
	spin_lock_irq(&callback_lock);

	if (cgroup_on_dfl(root_css->cgroup)) {
	} else {
	}

	spin_unlock_irq(&callback_lock);
	mutex_unlock(&gpu_mutex);
}

static struct gpu *gpu_attach_old_cs;

static int gpu_can_attach(struct cgroup_subsys_state *css,
					struct cgroup_taskset *tset)
{
	struct gpu *cs = css_cs(css);
//	struct task_struct *task;
	int ret;

	gpu_attach_old_cs = task_cs(cgroup_taskset_first(tset));

	mutex_lock(&gpu_mutex);

	ret = -ENOSPC;
	ret = 0;
//out_unlock:
	mutex_unlock(&gpu_mutex);
	return ret;
}

static void gpu_cancel_attach(struct cgroup_subsys_state *css,
					struct cgroup_taskset *tset)
{
	mutex_lock(&gpu_mutex);
	// css_cs(css)->attach_in_progress--;
	mutex_unlock(&gpu_mutex);
}

static void gpu_attach(struct cgroup_subsys_state *css,
					struct cgroup_taskset *tset)
{
	// struct task_struct *task;
	// struct task_struct *leader = cgroup_taskset_first(tset);
	// struct gpu *cs = css_cs(css);
	// struct gpu *oldcs = gpu_attach_old_cs;

	mutex_lock(&gpu_mutex);

	mutex_unlock(&gpu_mutex);
}

struct cgroup_subsys gpu_cgrp_subsys = {
	.css_alloc = gpu_css_alloc,
	.css_online = gpu_css_online,
	.css_offline = gpu_css_offline,
	.css_free = gpu_css_free,
	.can_attach = gpu_can_attach,
	.cancel_attach = gpu_cancel_attach,
	.attach = gpu_attach,
	.bind = gpu_bind,
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

