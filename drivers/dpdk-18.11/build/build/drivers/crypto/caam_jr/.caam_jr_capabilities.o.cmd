cmd_caam_jr_capabilities.o = gcc -Wp,-MD,./.caam_jr_capabilities.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/root/onvm-mos-master/drivers/dpdk-18.11/build/include -include /root/onvm-mos-master/drivers/dpdk-18.11/build/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -D _GNU_SOURCE -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-address-of-packed-member -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa/include -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/crypto/caam_jr -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/crypto/dpaa2_sec/ -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/common/include -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/linuxapp/eal    -o caam_jr_capabilities.o -c /root/onvm-mos-master/drivers/dpdk-18.11/drivers/crypto/caam_jr/caam_jr_capabilities.c 
