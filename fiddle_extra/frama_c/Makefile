ARGS= -load-script machdep_arm.ml -machdep arm -load-script dest_analysis.ml  -big-ints-hex 0  -absolute-valid-range 0x40000000-0xffffffff  -val-initialization-padding-globals=no  -const-writable -constfold -val -then -dst
QUIET_ARGS=-kernel-verbose 0 -value-verbose 0
UBOOT=~/u-boot-frama-c
run:
	frama-c ${UBOOT}/mem-common.i ${ARGS} ${QUIET_ARGS} -main gpmc_init

test:
	frama-c ${UBOOT}/boot-common-patched.i ${UBOOT}/beagle-patched.i ${UBOOT}/board-patched.i ${UBOOT}/omap_gpio-patched.i  ${UBOOT}/boot.i ${UBOOT}/mem-common.i ${UBOOT}/spl-patched.i -main board_init_r  ${ARGS}

testgd:
	frama-c ${UBOOT}/boot-common-patched.i  -main save_omap_boot_params  -dst-more ${QUIET_ARGS}  ${ARGS} 


testspl:
	frama-c ${UBOOT}/spl-patched.i -dst-more   -main board_init_r  ${ARGS}
