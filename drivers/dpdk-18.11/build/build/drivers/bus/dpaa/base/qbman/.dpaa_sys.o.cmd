cmd_base/qbman/dpaa_sys.o = gcc -Wp,-MD,base/qbman/.dpaa_sys.o.d.tmp  -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/root/onvm-mos-master/drivers/dpdk-18.11/build/include -include /root/onvm-mos-master/drivers/dpdk-18.11/build/include/rte_config.h -D_GNU_SOURCE -DALLOW_EXPERIMENTAL_API -O3 -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings -Wdeprecated -Wimplicit-fallthrough=2 -Wno-format-truncation -Wno-address-of-packed-member -Wno-pointer-arith -Wno-cast-qual -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa/ -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa/include -I/root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa/base/qbman -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/linuxapp/eal -I/root/onvm-mos-master/drivers/dpdk-18.11/lib/librte_eal/common/include    -o base/qbman/dpaa_sys.o -c /root/onvm-mos-master/drivers/dpdk-18.11/drivers/bus/dpaa/base/qbman/dpaa_sys.c 
