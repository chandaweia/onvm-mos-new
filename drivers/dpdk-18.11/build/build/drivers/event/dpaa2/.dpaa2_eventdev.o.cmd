cmd_dpaa2_eventdev.o = gcc -Wp,-MD,./.dpaa2_eventdev.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/root/onvm-mos-master/drivers/dpdk-18.11/build/include -include /root/onvm-mos-master/drivers/dpdk-18.11/build/include/rte_config.h -D_GNU_SOURCE -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-address-of-packed-member -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/qbman/include -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/mc -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/fslmc/portal -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/mempool/dpaa2 -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/event/dpaa2 -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/linuxapp/eal -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/net/dpaa2 -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/net/dpaa2/mc -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/crypto/dpaa2_sec -DALLOW_EXPERIMENTAL_API    -o dpaa2_eventdev.o -c /root/onvm-mos-master/drivers/dpdk-18.11/drivers/event/dpaa2/dpaa2_eventdev.c 
