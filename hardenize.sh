#!/bin/bash

# Colors
NC="\033[0m"
NL="\n"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
RED="\033[1;31m"
WHITE="\033[1;37m"
PURPLE="\033[1;35m"

# Check
echo -e "${NL}${WHITE}Checking ${PURPLE}Kernel${WHITE} values...${NC}${NL}"
echo -e "${WHITE}Checking ${BLUE}'kernel.kptr_restrict'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.kptr_restrict) -eq 2 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${GREEN}2${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${RED}$(sysctl -b kernel.kptr_restrict)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.dmesg_restrict'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.dmesg_restrict) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b kernel.dmesg_restrict)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.printk'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.printk) == "3 3 3 3" ]]; then
	echo -e "${WHITE}Expected: ${GREEN}3 3 3 3${WHITE} / Found: ${GREEN}3 3 3 3${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}3 3 3 3${WHITE} / Found: ${RED}$(sysctl -b kernel.printk)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.unprivileged_bpf_disabled'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.unprivileged_bpf_disabled) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b kernel.unprivileged_bpf_disabled)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.core.bpf_jit_harden'${WHITE}...${NC}"
if [[ $(sysctl -b net.core.bpf_jit_harden) -eq 2 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${GREEN}2${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${RED}$(sysctl -b net.core.bpf_jit_harden)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'dev.tty.ldisc_autoload'${WHITE}...${NC}"
if [[ $(sysctl -b dev.tty.ldisc_autoload) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b dev.tty.ldisc_autoload)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'vm.unprivileged_userfaultfd'${WHITE}...${NC}"
if [[ $(sysctl -b vm.unprivileged_userfaultfd) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b vm.unprivileged_userfaultfd)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.kexec_load_disabled'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.kexec_load_disabled) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b kernel.kexec_load_disabled)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.sysrq'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.sysrq) -eq 4 || $(sysctl -b kernel.sysrq) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}4${WHITE} or ${GREEN}0${WHITE} / Found: ${GREEN}$(sysctl -b kernel.sysrq)${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}4${WHITE} or ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b kernel.sysrq)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.unprivileged_userns_clone'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.unprivileged_userns_clone) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b kernel.unprivileged_userns_clone)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'kernel.perf_event_paranoid'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.perf_event_paranoid) -eq 3 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}3${WHITE} / Found: ${GREEN}3${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}3${WHITE} / Found: ${RED}$(sysctl -b kernel.perf_event_paranoid)${NC}"
fi

echo -e "${NL}${WHITE}Checking ${PURPLE}Network${WHITE} values...${NC}${NL}"

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.tcp_syncookies'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.tcp_syncookies) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.tcp_syncookies)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.tcp_rfc1337'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.tcp_rfc1337) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.tcp_rfc1337)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.all.rp_filter'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.all.rp_filter) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.all.rp_filter)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.default.rp_filter'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.default.rp_filter) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.default.rp_filter)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.all.accept_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.all.accept_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.all.accept_redirects)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.default.accept_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.default.accept_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.default.accept_redirects)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.all.secure_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.all.secure_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.all.secure_redirects)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.default.secure_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.default.secure_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.default.secure_redirects)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.all.accept_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.all.accept_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.all.accept_redirects)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.default.accept_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.default.accept_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.default.accept_redirects)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.all.send_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.all.send_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.all.send_redirects)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.default.send_redirects'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.default.send_redirects) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.default.send_redirects)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.icmp_echo_ignore_all'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.icmp_echo_ignore_all) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.icmp_echo_ignore_all)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.all.accept_source_route'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.all.accept_source_route) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.all.accept_source_route)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.conf.default.accept_source_route'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.conf.default.accept_source_route) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.conf.default.accept_source_route)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.all.accept_source_route'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.all.accept_source_route) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.all.accept_source_route)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.default.accept_source_route'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.default.accept_source_route) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.default.accept_source_route)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.all.accept_ra'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.all.accept_ra) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.all.accept_ra)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv6.conf.default.accept_ra'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv6.conf.default.accept_ra) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv6.conf.default.accept_ra)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'net.ipv4.tcp_sack'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.tcp_sack) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.tcp_sack)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.tcp_dsack'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.tcp_dsack) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.tcp_dsack)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'net.ipv4.tcp_fack'${WHITE}...${NC}"
if [[ $(sysctl -b net.ipv4.tcp_fack) -eq 0 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${GREEN}0${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}0${WHITE} / Found: ${RED}$(sysctl -b net.ipv4.tcp_fack)${NC}"
fi

echo -e "${NL}${WHITE}Checking ${PURPLE}User space${WHITE} values...${NC}${NL}"
echo -e "${WHITE}Checking ${BLUE}'kernel.yama.ptrace_scope'${WHITE}...${NC}"
if [[ $(sysctl -b kernel.yama.ptrace_scope) -eq 2 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${GREEN}2${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${RED}$(sysctl -b kernel.yama.ptrace_scope)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'vm.mmap_rnd_bits'${WHITE}...${NC}"
if [[ $(sysctl -b vm.mmap_rnd_bits) -eq 32 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}32${WHITE} / Found: ${GREEN}32${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}32${WHITE} / Found: ${RED}$(sysctl -b vm.mmap_rnd_bits)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'vm.mmap_rnd_compat_bits'${WHITE}...${NC}"
if [[ $(sysctl -b vm.mmap_rnd_compat_bits) -eq 16 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}16${WHITE} / Found: ${GREEN}16${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}16${WHITE} / Found: ${RED}$(sysctl -b vm.mmap_rnd_compat_bits)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'fs.protected_symlinks'${WHITE}...${NC}"
if [[ $(sysctl -b fs.protected_symlinks) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b fs.protected_symlinks)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'fs.protected_hardlinks'${WHITE}...${NC}"
if [[ $(sysctl -b fs.protected_hardlinks) -eq 1 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${GREEN}1${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}1${WHITE} / Found: ${RED}$(sysctl -b fs.protected_hardlinks)${NC}"
fi

echo -e "${WHITE}Checking ${BLUE}'fs.protected_fifos'${WHITE}...${NC}"
if [[ $(sysctl -b fs.protected_fifos) -eq 2 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${GREEN}2${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${RED}$(sysctl -b fs.protected_fifos)${NC}"
fi
echo -e "${WHITE}Checking ${BLUE}'fs.protected_regular'${WHITE}...${NC}"
if [[ $(sysctl -b fs.protected_regular) -eq 2 ]]; then
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${GREEN}2${NC}"
else
	echo -e "${WHITE}Expected: ${GREEN}2${WHITE} / Found: ${RED}$(sysctl -b fs.protected_regular)${NC}"
fi

echo -e "${NL}${WHITE}Checking ${PURPLE}Boot${WHITE} values...${NC}"
if [[ $(which kernelstub | wc -l) -eq 1 ]]; then
	echo -e "${WHITE}Reading values from ${PURPLE}$(which kernelstub)${WHITE}...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'slab'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "slab_nomerge" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'slub_debug'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "slub_debug=FZ" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'init_on_allo, init_on_free'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "init_on_alloc=1 init_on_free=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'page_alloc.shuffle'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "page_alloc.shuffle=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'pti'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "pti=on" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'vsyscall'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "vsyscall=none" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'debugfs'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "debugfs=off" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'oops'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "oops=panic" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${RED}Not Found${NC}"
	fi


	echo -e "${WHITE}Checking ${BLUE}'module.sig_enforce'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "module.sig_enforce=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'lockdown'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "lockdown=confidentiality" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'mce'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "mce=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'loglevel'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${NL}${WHITE}Checking ${PURPLE}CPU${WHITE} values...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'mitigations'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'recommended values'${WHITE}...${NC}"
	if [[ $(kernelstub -p 2>&1 | grep -i "kernel boot" | grep -i "slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${RED}Not Found${NC}"
	fi
elif [[ -f /etc/default/grub ]]; then
	echo -e "${WHITE}Reading values from ${PURPLE}/etc/default/grub${WHITE}...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'slab'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "slab_nomerge" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'slub_debug'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "slub_debug=FZ" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'init_on_allo, init_on_free'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "init_on_alloc=1 init_on_free=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'page_alloc.shuffle'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "page_alloc.shuffle=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'pti'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "pti=on" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'vsyscall'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "vsyscall=none" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'debugfs'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "debugfs=off" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'oops'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "oops=panic" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${RED}Not Found${NC}"
	fi


	echo -e "${WHITE}Checking ${BLUE}'module.sig_enforce'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "module.sig_enforce=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'lockdown'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "lockdown=confidentiality" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'mce'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "mce=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'loglevel'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${NL}${WHITE}Checking ${PURPLE}CPU${WHITE} values...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'mitigations'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'recommended values'${WHITE}...${NC}"
	if [[ $(cat /etc/default/grub | grep -i "slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${RED}Not Found${NC}"
	fi
elif [[ -f /boot/syslinux/syslinux.cfg ]]; then
	echo -e "${WHITE}Reading values from ${PURPLE}/boot/syslinux/syslinux.cfg${WHITE}...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'slab'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "slab_nomerge" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'slub_debug'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "slub_debug=FZ" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slub_debug=FZ${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'init_on_allo, init_on_free'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "init_on_alloc=1 init_on_free=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}init_on_alloc=1 init_on_free=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'page_alloc.shuffle'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "page_alloc.shuffle=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}page_alloc.shuffle=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'pti'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "pti=on" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}pti=on${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'vsyscall'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "vsyscall=none" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}vsyscall=none${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'debugfs'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "debugfs=off" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}debugfs=off${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'oops'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "oops=panic" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}oops=panic${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'module.sig_enforce'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "module.sig_enforce=1" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}module.sig_enforce=1${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'lockdown'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "lockdown=confidentiality" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}lockdown=confidentiality${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'mce'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "mce=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}mce=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'loglevel'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}quiet loglevel=0${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${NL}${WHITE}Checking ${PURPLE}CPU${WHITE} values...${NC}${NL}"
	echo -e "${WHITE}Checking ${BLUE}'mitigations'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}spectre_v2,spec_store_bypass_disable,tsx,tsx_async_abort,mds,l1tf,nosmt,kvm.nx_huge_pages${WHITE} / ${RED}Not Found${NC}"
	fi

	echo -e "${WHITE}Checking ${BLUE}'recommended values'${WHITE}...${NC}"
	if [[ $(cat /boot/syslinux/syslinux.cfg | grep -i "slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0" | wc -l) -eq 1 ]]; then
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${GREEN}Found${NC}"
	else
		echo -e "${WHITE}Expected: ${GREEN}slab_nomerge,slub_debug,init_on_alloc,init_on_free,page_alloc.shuffle,pti,vsyscall,debugfs,oops,module.sig_enforce,lockdown,mce,quiet,loglevel${WHITE} / ${RED}Not Found${NC}"
	fi
fi

# Patch
echo -e "${NC}${NL}"
