# match assembly generated with gcc -S ../signal_handler.c -fno-stack-protector -O
signal_handler:
.LFB0 = .
	addi.d	$r3,$r3,-1488
	st.d	$r1,$r3,1480
	st.d	$r23,$r3,1472
	st.d	$r24,$r3,1464
	st.d	$r25,$r3,1456
	lu12i.w	$r13,-4096>>12			# 0xfffffffffffff000
	add.d	$r3,$r3,$r13
	or	$r25,$r6,$r0
	lu12i.w	$r23,-8192>>12			# 0xffffffffffffe000
	ori	$r23,$r23,2671
	lu12i.w	$r12,4096>>12			# 0x1000
	ori	$r12,$r12,1456
	add.d	$r12,$r12,$r23
	add.d	$r23,$r12,$r3
	srli.d	$r23,$r23,5
	slli.d	$r23,$r23,5
	ldptr.d	$r12,$r6,0
	stptr.d	$r12,$r23,0
	st.d	$r0,$r23,8
	ld.d	$r12,$r6,16
	st.d	$r12,$r23,16
	ld.d	$r12,$r6,24
	st.d	$r12,$r23,24
	ld.d	$r12,$r6,32
	st.d	$r12,$r23,32
	ld.d	$r12,$r6,40
	stptr.d	$r12,$r23,5504
	ld.d	$r12,$r6,176
	st.d	$r12,$r23,64
	or	$r12,$r0,$r0
	addi.d	$r24,$r6,184
	addi.w	$r15,$r0,256			# 0x100
.L2:
	add.d	$r13,$r23,$r12
	ldx.d	$r14,$r24,$r12
	st.d	$r14,$r13,72
	addi.d	$r12,$r12,8
	bne	$r12,$r15,.L2
	ldptr.w	$r12,$r25,440
	st.w	$r12,$r23,328
	or	$r6,$r23,$r0
	jirl	$r1,$r7,0
	ldptr.d	$r12,$r23,0
	stptr.d	$r12,$r25,0
	st.d	$r0,$r25,8
	ld.d	$r12,$r23,16
	st.d	$r12,$r25,16
	ld.d	$r12,$r23,24
	st.d	$r12,$r25,24
	ld.d	$r12,$r23,32
	st.d	$r12,$r25,32
	ldptr.d	$r12,$r23,5504
	st.d	$r12,$r25,40
	ld.d	$r12,$r23,64
	st.d	$r12,$r25,176
	or	$r12,$r0,$r0
	addi.w	$r14,$r0,256			# 0x100
.L3:
	add.d	$r13,$r23,$r12
	ld.d	$r13,$r13,72
	stx.d	$r13,$r24,$r12
	addi.d	$r12,$r12,8
	bne	$r12,$r14,.L3
	ldptr.w	$r12,$r23,328
	st.w	$r12,$r25,440
	lu12i.w	$r13,4096>>12			# 0x1000
	add.d	$r3,$r3,$r13
	ld.d	$r1,$r3,1480
	ld.d	$r23,$r3,1472
	ld.d	$r24,$r3,1464
	ld.d	$r25,$r3,1456
	addi.d	$r3,$r3,1488
	jr	$r1

	# trampoline
trampoline:
	lu12i.w	$r7, %abs_hi20(.real_signal_handler)
	ori $r7, $r7, %abs_lo12(.real_signal_handler)
	lu32i.d $r7, %abs64_lo20(.real_signal_handler)
	lu52i.d $r7, $r7, %abs64_hi12(.real_signal_handler)
	b .real_signal_handler

.real_signal_handler:
