cmd_fslmc_bus.o = gcc -Wp,-MD,./.fslmc_bus.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/root/onvm-mos-master/drivers/dpdk-18.11/x86_64-native-linuxapp-gcc/include -include /root/onvm-mos-master/drivers/dpdk-18.11/x86_64-native-linuxapp-gcc/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-address-of-packed-member -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/mc -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/qbman/include -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/common    -o fslmc_bus.o -c /root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/fslmc_bus.c 
