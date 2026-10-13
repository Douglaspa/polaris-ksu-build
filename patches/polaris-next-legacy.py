#!/usr/bin/env python3
import pathlib,sys
root=pathlib.Path(sys.argv[1]); guard='#ifdef CONFIG_KSU\n'
def edit(rel,a,b):
 p=root/rel; s=p.read_text(); assert s.count(a)==1,(rel,s.count(a)); p.write_text(s.replace(a,b))
def hook(rel,fn,decl,anchor,call):
 p=root/rel;s=p.read_text();start=s.index(fn); brace=s.index('{',start);end=s.index('\n}',brace)+2; body=s[start:end];assert body.count(anchor)==1,(fn,anchor)
 body=body.replace(anchor,guard+call+'\n#endif\n'+anchor)
 s=s[:start]+guard+decl+'\n#endif\n'+body+s[end:];p.write_text(s)
hook('fs/exec.c','static int do_execveat_common(', 'extern int ksu_handle_execveat(int *, struct filename **, void *, void *, int *);', '\tif (IS_ERR(filename))', '\tksu_handle_execveat(&fd,&filename,&argv,&envp,&flags);')
hook('fs/open.c','SYSCALL_DEFINE3(faccessat,','extern int ksu_handle_faccessat(int *,const char __user **,int *,int *);','\tif (mode & ~S_IRWXO)','\tksu_handle_faccessat(&dfd,&filename,&mode,NULL);')
for fn in ['SYSCALL_DEFINE4(newfstatat,','SYSCALL_DEFINE4(fstatat64,']:
 hook('fs/stat.c',fn,'extern int ksu_handle_stat(int *,const char __user **,int *);','\terror = vfs_fstatat(dfd, filename, &stat, flag);','\tksu_handle_stat(&dfd,&filename,&flag);')
hook('fs/stat.c','SYSCALL_DEFINE2(newfstat,','extern void ksu_handle_newfstat_ret(unsigned int *,struct stat __user **);','\treturn error;','\tif (!error) ksu_handle_newfstat_ret(&fd,&statbuf);')
hook('fs/stat.c','SYSCALL_DEFINE2(fstat64,','extern void ksu_handle_fstat64_ret(unsigned long *,struct stat64 __user **);','\treturn error;','\tif (!error) ksu_handle_fstat64_ret(&fd,&statbuf);')
hook('fs/read_write.c','ssize_t vfs_read(','extern int ksu_handle_vfs_read(struct file **,char __user **,size_t *,loff_t **);','\tif (!(file->f_mode & FMODE_READ))','\tksu_handle_vfs_read(&file,&buf,&count,&pos);')
hook('kernel/reboot.c','SYSCALL_DEFINE4(reboot,','extern int ksu_handle_sys_reboot(int,int,unsigned int,void __user **);','\t/* We only trust the superuser with rebooting the system. */','\tksu_handle_sys_reboot(magic1,magic2,cmd,&arg);')
hook('drivers/input/input.c','static void input_handle_event(','extern int ksu_handle_input_handle_event(unsigned int *,unsigned int *,int *);','\tint disposition = input_get_disposition(dev, type, code, &value);','\tksu_handle_input_handle_event(&type,&code,&value);')
# Keep declaration-before-statements in the input hook.
edit('drivers/input/input.c',guard+'\tksu_handle_input_handle_event(&type,&code,&value);\n#endif\n\tint disposition = input_get_disposition(dev, type, code, &value);','\tint disposition;\n'+guard+'\tksu_handle_input_handle_event(&type,&code,&value);\n#endif\n\tdisposition = input_get_disposition(dev, type, code, &value);')
edit('security/selinux/hooks.c','\trc = security_bounded_transition(old_tsec->sid, new_tsec->sid);',guard+'''\t{
\t\tu32 init_sid, su_sid;
\t\tif (!security_secctx_to_secid("u:r:init:s0", 11, &init_sid) &&
\t\t    !security_secctx_to_secid("u:r:su:s0", 9, &su_sid) &&
\t\t    old_tsec->sid == init_sid && new_tsec->sid == su_sid)
\t\t\treturn 0;
\t}
#endif
\trc = security_bounded_transition(old_tsec->sid, new_tsec->sid);''')
k=root/'KernelSU-Next/kernel'
for p in k.rglob('*'):
 if p.suffix in ('.c','.h'):
  s=p.read_text();p.write_text(s.replace('#include <linux/compiler_types.h>','#include <linux/compiler.h>'))
p=k/'core/init.c';s=p.read_text();a='#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)';assert s.count(a)==1;p.write_text(s.replace(a,'#ifndef MODULE_IMPORT_NS\n#define MODULE_IMPORT_NS(ns)\n#endif\n'+a))
print('Applied typed source-level manual hooks. No syscall table ABI casts.')
