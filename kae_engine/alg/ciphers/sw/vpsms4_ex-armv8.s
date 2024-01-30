





.arch armv8-a+crypto
.text

.type _vpsm4_ex_consts,%object
.align 7
_vpsm4_ex_consts:
.Lck:
.long 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
.long 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
.long 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
.long 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
.long 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
.long 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
.long 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
.long 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
.Lfk:
.quad 0x56aa3350a3b1bac6,0xb27022dc677d9197
.Lshuffles:
.quad 0x0B0A090807060504,0x030201000F0E0D0C
.Lxts_magic:
.quad 0x0101010101010187,0x0101010101010101
.Lsbox_magic:
.quad 0x0b0e0104070a0d00,0x0306090c0f020508
.quad 0x62185a2042387a00,0x22581a6002783a40
.quad 0x15df62a89e54e923,0xc10bb67c4a803df7
.quad 0xb9aa6b78c1d21300,0x1407c6d56c7fbead
.quad 0x6404462679195b3b,0xe383c1a1fe9edcbc
.quad 0x0f0f0f0f0f0f0f0f,0x0f0f0f0f0f0f0f0f

.size _vpsm4_ex_consts,.-_vpsm4_ex_consts
.type _vpsm4_ex_set_key,%function
.align 4
_vpsm4_ex_set_key:

 ld1 {v5.4s},[x0]
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80

 rev32 v5.16b,v5.16b

 adr x5,.Lshuffles
 ld1 {v7.2d},[x5]
 adr x5,.Lfk
 ld1 {v6.2d},[x5]
 eor v5.16b,v5.16b,v6.16b
 mov x6,#32
 adr x5,.Lck
 movi v0.16b,#64
 cbnz w2,1f
 add x1,x1,124
1:
 mov w7,v5.s[1]
 ldr w8,[x5],#4
 eor w8,w8,w7
 mov w7,v5.s[2]
 eor w8,w8,w7
 mov w7,v5.s[3]
 eor w8,w8,w7

 mov v4.s[0],w8
 tbl v0.16b, {v4.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 mov w7,v0.s[0]
 eor w8,w7,w7,ror #19
 eor w8,w8,w7,ror #9
 mov w7,v5.s[0]
 eor w8,w8,w7
 mov v5.s[0],w8
 cbz w2,2f
 str w8,[x1],#4
 b 3f
2:
 str w8,[x1],#-4
3:
 tbl v5.16b,{v5.16b},v7.16b
 subs x6,x6,#1
 b.ne 1b
 ret
.size _vpsm4_ex_set_key,.-_vpsm4_ex_set_key
.type _vpsm4_ex_enc_4blks,%function
.align 4
_vpsm4_ex_enc_4blks:

 mov x10,x3
 mov w11,#8
10:
 ldp w7,w8,[x10],8
 dup v12.4s,w7
 dup v13.4s,w8


 eor v14.16b,v6.16b,v7.16b
 eor v12.16b,v5.16b,v12.16b
 eor v12.16b,v14.16b,v12.16b

 tbl v0.16b, {v12.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 mov v12.16b,v0.16b


 ushr v0.4s,v12.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 eor v4.16b,v4.16b,v12.16b


 eor v14.16b,v14.16b,v4.16b
 eor v13.16b,v14.16b,v13.16b

 tbl v0.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 mov v13.16b,v0.16b


 ushr v0.4s,v13.4s,32-2
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v0.4s,v13.4s,2
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v0.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 ldp w7,w8,[x10],8
 eor v5.16b,v5.16b,v13.16b

 dup v12.4s,w7
 dup v13.4s,w8


 eor v14.16b,v4.16b,v5.16b
 eor v12.16b,v7.16b,v12.16b
 eor v12.16b,v14.16b,v12.16b

 tbl v0.16b, {v12.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 mov v12.16b,v0.16b


 ushr v0.4s,v12.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 eor v6.16b,v6.16b,v12.16b


 eor v14.16b,v14.16b,v6.16b
 eor v13.16b,v14.16b,v13.16b

 tbl v0.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 mov v13.16b,v0.16b


 ushr v0.4s,v13.4s,32-2
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v0.4s,v13.4s,2
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v0.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 eor v7.16b,v7.16b,v13.16b
 subs w11,w11,#1
 b.ne 10b

 rev32 v3.16b,v4.16b




 rev32 v2.16b,v5.16b




 rev32 v1.16b,v6.16b




 rev32 v0.16b,v7.16b



 ret
.size _vpsm4_ex_enc_4blks,.-_vpsm4_ex_enc_4blks
.type _vpsm4_ex_enc_8blks,%function
.align 4
_vpsm4_ex_enc_8blks:

 mov x10,x3
 mov w11,#8
10:
 ldp w7,w8,[x10],8

 dup v12.4s,w7
 eor v14.16b,v6.16b,v7.16b
 eor v15.16b,v10.16b,v11.16b
 eor v0.16b,v5.16b,v12.16b
 eor v1.16b,v9.16b,v12.16b
 eor v12.16b,v14.16b,v0.16b
 eor v13.16b,v15.16b,v1.16b

 tbl v0.16b, {v12.16b}, v26.16b
 tbl v1.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v28.16b}, v1.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 eor v25.16b, v25.16b, v25.16b
 aese v0.16b,v25.16b
 aese v1.16b,v25.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v30.16b}, v1.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 mov v12.16b,v0.16b
 mov v13.16b,v1.16b


 ushr v0.4s,v12.4s,32-2
 ushr v25.4s,v13.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v25.4s,v13.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v25.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 eor v4.16b,v4.16b,v12.16b
 eor v8.16b,v8.16b,v13.16b


 dup v13.4s,w8
 eor v14.16b,v14.16b,v4.16b
 eor v15.16b,v15.16b,v8.16b
 eor v12.16b,v14.16b,v13.16b
 eor v13.16b,v15.16b,v13.16b

 tbl v0.16b, {v12.16b}, v26.16b
 tbl v1.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v28.16b}, v1.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 eor v25.16b, v25.16b, v25.16b
 aese v0.16b,v25.16b
 aese v1.16b,v25.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v30.16b}, v1.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 mov v12.16b,v0.16b
 mov v13.16b,v1.16b


 ushr v0.4s,v12.4s,32-2
 ushr v25.4s,v13.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v25.4s,v13.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v25.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 ldp w7,w8,[x10],8
 eor v5.16b,v5.16b,v12.16b
 eor v9.16b,v9.16b,v13.16b


 dup v12.4s,w7
 eor v14.16b,v4.16b,v5.16b
 eor v15.16b,v8.16b,v9.16b
 eor v0.16b,v7.16b,v12.16b
 eor v1.16b,v11.16b,v12.16b
 eor v12.16b,v14.16b,v0.16b
 eor v13.16b,v15.16b,v1.16b

 tbl v0.16b, {v12.16b}, v26.16b
 tbl v1.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v28.16b}, v1.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 eor v25.16b, v25.16b, v25.16b
 aese v0.16b,v25.16b
 aese v1.16b,v25.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v30.16b}, v1.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 mov v12.16b,v0.16b
 mov v13.16b,v1.16b


 ushr v0.4s,v12.4s,32-2
 ushr v25.4s,v13.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v25.4s,v13.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v25.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 eor v6.16b,v6.16b,v12.16b
 eor v10.16b,v10.16b,v13.16b


 dup v13.4s,w8
 eor v14.16b,v14.16b,v6.16b
 eor v15.16b,v15.16b,v10.16b
 eor v12.16b,v14.16b,v13.16b
 eor v13.16b,v15.16b,v13.16b

 tbl v0.16b, {v12.16b}, v26.16b
 tbl v1.16b, {v13.16b}, v26.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v28.16b}, v1.16b
 tbl v24.16b, {v27.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 eor v25.16b, v25.16b, v25.16b
 aese v0.16b,v25.16b
 aese v1.16b,v25.16b
 ushr v24.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v0.16b, v0.16b, v24.16b
 ushr v24.16b, v1.16b, 4
 and v1.16b, v1.16b, v31.16b
 tbl v1.16b, {v30.16b}, v1.16b
 tbl v24.16b, {v29.16b}, v24.16b
 eor v1.16b, v1.16b, v24.16b
 mov v12.16b,v0.16b
 mov v13.16b,v1.16b


 ushr v0.4s,v12.4s,32-2
 ushr v25.4s,v13.4s,32-2
 ushr v1.4s,v12.4s,32-10
 ushr v2.4s,v12.4s,32-18
 ushr v3.4s,v12.4s,32-24
 sli v0.4s,v12.4s,2
 sli v25.4s,v13.4s,2
 sli v1.4s,v12.4s,10
 sli v2.4s,v12.4s,18
 sli v3.4s,v12.4s,24
 eor v24.16b,v0.16b,v12.16b
 eor v24.16b,v24.16b,v1.16b
 eor v12.16b,v2.16b,v3.16b
 eor v12.16b,v12.16b,v24.16b
 ushr v1.4s,v13.4s,32-10
 ushr v2.4s,v13.4s,32-18
 ushr v3.4s,v13.4s,32-24
 sli v1.4s,v13.4s,10
 sli v2.4s,v13.4s,18
 sli v3.4s,v13.4s,24
 eor v24.16b,v25.16b,v13.16b
 eor v24.16b,v24.16b,v1.16b
 eor v13.16b,v2.16b,v3.16b
 eor v13.16b,v13.16b,v24.16b
 eor v7.16b,v7.16b,v12.16b
 eor v11.16b,v11.16b,v13.16b
 subs w11,w11,#1
 b.ne 10b

 rev32 v3.16b,v4.16b




 rev32 v2.16b,v5.16b




 rev32 v1.16b,v6.16b




 rev32 v0.16b,v7.16b




 rev32 v7.16b,v8.16b




 rev32 v6.16b,v9.16b




 rev32 v5.16b,v10.16b




 rev32 v4.16b,v11.16b



 ret
.size _vpsm4_ex_enc_8blks,.-_vpsm4_ex_enc_8blks
.globl vpsm4_ex_set_encrypt_key
.type vpsm4_ex_set_encrypt_key,%function
.align 5
vpsm4_ex_set_encrypt_key:

 stp x29,x30,[sp,#-16]!
 mov w2,1
 bl _vpsm4_ex_set_key
 ldp x29,x30,[sp],#16

 ret
.size vpsm4_ex_set_encrypt_key,.-vpsm4_ex_set_encrypt_key
.globl vpsm4_ex_set_decrypt_key
.type vpsm4_ex_set_decrypt_key,%function
.align 5
vpsm4_ex_set_decrypt_key:

 stp x29,x30,[sp,#-16]!
 mov w2,0
 bl _vpsm4_ex_set_key
 ldp x29,x30,[sp],#16

 ret
.size vpsm4_ex_set_decrypt_key,.-vpsm4_ex_set_decrypt_key
.globl vpsm4_ex_encrypt
.type vpsm4_ex_encrypt,%function
.align 5
vpsm4_ex_encrypt:

 ld1 {v4.4s},[x0]
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80

 rev32 v4.16b,v4.16b

 mov x3,x2
 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 st1 {v4.4s},[x1]
 ret
.size vpsm4_ex_encrypt,.-vpsm4_ex_encrypt
.globl vpsm4_ex_decrypt
.type vpsm4_ex_decrypt,%function
.align 5
vpsm4_ex_decrypt:

 ld1 {v4.4s},[x0]
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80

 rev32 v4.16b,v4.16b

 mov x3,x2
 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 st1 {v4.4s},[x1]
 ret
.size vpsm4_ex_decrypt,.-vpsm4_ex_decrypt
.globl vpsm4_ex_ecb_encrypt
.type vpsm4_ex_ecb_encrypt,%function
.align 5
vpsm4_ex_ecb_encrypt:


 lsr x2,x2,4
 stp d8,d9,[sp,#-80]!
 stp d10,d11,[sp,#16]
 stp d12,d13,[sp,#32]
 stp d14,d15,[sp,#48]
 stp x29,x30,[sp,#64]
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80
.Lecb_8_blocks_process:
 cmp w2,#8
 b.lt .Lecb_4_blocks_process
 ld4 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 ld4 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b


 rev32 v8.16b,v8.16b


 rev32 v9.16b,v9.16b


 rev32 v10.16b,v10.16b


 rev32 v11.16b,v11.16b

 bl _vpsm4_ex_enc_8blks
 st4 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 st4 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs w2,w2,#8
 b.gt .Lecb_8_blocks_process
 b 100f
.Lecb_4_blocks_process:
 cmp w2,#4
 b.lt 1f
 ld4 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 st4 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 sub w2,w2,#4
1:

 cmp w2,#1
 b.lt 100f
 b.gt 1f
 ld1 {v4.4s},[x0]

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 st1 {v4.4s},[x1]
 b 100f
1:
 ld4 {v4.s,v5.s,v6.s,v7.s}[0],[x0],#16
 ld4 {v4.s,v5.s,v6.s,v7.s}[1],[x0],#16
 cmp w2,#2
 b.gt 1f

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 st4 {v0.s,v1.s,v2.s,v3.s}[0],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[1],[x1]
 b 100f
1:
 ld4 {v4.s,v5.s,v6.s,v7.s}[2],[x0],#16

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 st4 {v0.s,v1.s,v2.s,v3.s}[0],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[1],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[2],[x1]
100:
 ldp d10,d11,[sp,#16]
 ldp d12,d13,[sp,#32]
 ldp d14,d15,[sp,#48]
 ldp x29,x30,[sp,#64]
 ldp d8,d9,[sp],#80

 ret
.size vpsm4_ex_ecb_encrypt,.-vpsm4_ex_ecb_encrypt
.globl vpsm4_ex_cbc_encrypt
.type vpsm4_ex_cbc_encrypt,%function
.align 5
vpsm4_ex_cbc_encrypt:

 lsr x2,x2,4
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80
 cbz w5,.Ldec
 ld1 {v3.4s},[x4]
.Lcbc_4_blocks_enc:
 cmp w2,#4
 b.lt 1f
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 eor v4.16b,v4.16b,v3.16b

 rev32 v5.16b,v5.16b


 rev32 v4.16b,v4.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12
 eor v5.16b,v5.16b,v4.16b
 mov x10,x3
 mov w11,#8
 mov w12,v5.s[0]
 mov w13,v5.s[1]
 mov w14,v5.s[2]
 mov w15,v5.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v5.s[0],w15
 mov v5.s[1],w14
 mov v5.s[2],w13
 mov v5.s[3],w12

 rev32 v4.16b,v4.16b

 eor v6.16b,v6.16b,v5.16b
 mov x10,x3
 mov w11,#8
 mov w12,v6.s[0]
 mov w13,v6.s[1]
 mov w14,v6.s[2]
 mov w15,v6.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v6.s[0],w15
 mov v6.s[1],w14
 mov v6.s[2],w13
 mov v6.s[3],w12

 rev32 v5.16b,v5.16b

 eor v7.16b,v7.16b,v6.16b
 mov x10,x3
 mov w11,#8
 mov w12,v7.s[0]
 mov w13,v7.s[1]
 mov w14,v7.s[2]
 mov w15,v7.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v7.s[0],w15
 mov v7.s[1],w14
 mov v7.s[2],w13
 mov v7.s[3],w12

 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 orr v3.16b,v7.16b,v7.16b
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs w2,w2,#4
 b.ne .Lcbc_4_blocks_enc
 b 2f
1:
 subs w2,w2,#1
 b.lt 2f
 ld1 {v4.4s},[x0],#16
 eor v3.16b,v3.16b,v4.16b

 rev32 v3.16b,v3.16b

 mov x10,x3
 mov w11,#8
 mov w12,v3.s[0]
 mov w13,v3.s[1]
 mov w14,v3.s[2]
 mov w15,v3.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v3.s[0],w15
 mov v3.s[1],w14
 mov v3.s[2],w13
 mov v3.s[3],w12

 rev32 v3.16b,v3.16b

 st1 {v3.4s},[x1],#16
 b 1b
2:

 st1 {v3.4s},[x4]
 ret

.Ldec:


 stp d8,d9,[sp,#-80]!
 stp d10,d11,[sp,#16]
 stp d12,d13,[sp,#32]
 stp d14,d15,[sp,#48]
 stp x29,x30,[sp,#64]
.Lcbc_8_blocks_dec:
 cmp w2,#8
 b.lt 1f
 ld4 {v4.4s,v5.4s,v6.4s,v7.4s},[x0]
 add x10,x0,#64
 ld4 {v8.4s,v9.4s,v10.4s,v11.4s},[x10]

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b


 rev32 v8.16b,v8.16b


 rev32 v9.16b,v9.16b


 rev32 v10.16b,v10.16b


 rev32 v11.16b,v11.16b

 bl _vpsm4_ex_enc_8blks
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 zip1 v8.4s,v4.4s,v5.4s
 zip2 v9.4s,v4.4s,v5.4s
 zip1 v10.4s,v6.4s,v7.4s
 zip2 v11.4s,v6.4s,v7.4s
 zip1 v4.2d,v8.2d,v10.2d
 zip2 v5.2d,v8.2d,v10.2d
 zip1 v6.2d,v9.2d,v11.2d
 zip2 v7.2d,v9.2d,v11.2d
 ld1 {v15.4s},[x4]
 ld1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64


 eor v0.16b,v0.16b,v15.16b
 ld1 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 eor v1.16b,v1.16b,v8.16b
 eor v2.16b,v2.16b,v9.16b
 eor v3.16b,v3.16b,v10.16b

 st1 {v15.4s}, [x4]
 eor v4.16b,v4.16b,v11.16b
 eor v5.16b,v5.16b,v12.16b
 eor v6.16b,v6.16b,v13.16b
 eor v7.16b,v7.16b,v14.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs w2,w2,#8
 b.gt .Lcbc_8_blocks_dec
 b.eq 100f
1:
 ld1 {v15.4s},[x4]
.Lcbc_4_blocks_dec:
 cmp w2,#4
 b.lt 1f
 ld4 {v4.4s,v5.4s,v6.4s,v7.4s},[x0]

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 eor v0.16b,v0.16b,v15.16b
 eor v1.16b,v1.16b,v4.16b
 orr v15.16b,v7.16b,v7.16b
 eor v2.16b,v2.16b,v5.16b
 eor v3.16b,v3.16b,v6.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 subs w2,w2,#4
 b.gt .Lcbc_4_blocks_dec

 st1 {v7.4s}, [x4]
 b 100f
1:
 subs w2,w2,#1
 b.lt 100f
 b.gt 1f
 ld1 {v4.4s},[x0],#16

 st1 {v4.4s}, [x4]

 rev32 v8.16b,v4.16b



 mov x10,x3
 mov w11,#8
 mov w12,v8.s[0]
 mov w13,v8.s[1]
 mov w14,v8.s[2]
 mov w15,v8.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v8.s[0],w15
 mov v8.s[1],w14
 mov v8.s[2],w13
 mov v8.s[3],w12

 rev32 v8.16b,v8.16b

 eor v8.16b,v8.16b,v15.16b
 st1 {v8.4s},[x1],#16
 b 100f
1:
 ld4 {v4.s,v5.s,v6.s,v7.s}[0],[x0]
 add x10,x0,#16
 ld4 {v4.s,v5.s,v6.s,v7.s}[1],[x10],#16
 subs w2,w2,1
 b.gt 1f

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 ld1 {v4.4s,v5.4s},[x0],#32
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 eor v0.16b,v0.16b,v15.16b
 eor v1.16b,v1.16b,v4.16b
 st1 {v0.4s,v1.4s},[x1],#32

 st1 {v5.4s}, [x4]
 b 100f
1:
 ld4 {v4.s,v5.s,v6.s,v7.s}[2],[x10]

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 bl _vpsm4_ex_enc_4blks
 ld1 {v4.4s,v5.4s,v6.4s},[x0],#48
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 eor v0.16b,v0.16b,v15.16b
 eor v1.16b,v1.16b,v4.16b
 eor v2.16b,v2.16b,v5.16b
 st1 {v0.4s,v1.4s,v2.4s},[x1],#48

 st1 {v6.4s}, [x4]
100:
 ldp d10,d11,[sp,#16]
 ldp d12,d13,[sp,#32]
 ldp d14,d15,[sp,#48]
 ldp x29,x30,[sp,#64]
 ldp d8,d9,[sp],#80

 ret
.size vpsm4_ex_cbc_encrypt,.-vpsm4_ex_cbc_encrypt
.globl vpsm4_ex_ctr32_encrypt_blocks
.type vpsm4_ex_ctr32_encrypt_blocks,%function
.align 5
vpsm4_ex_ctr32_encrypt_blocks:

 ld1 {v3.4s},[x4]

 rev32 v3.16b,v3.16b

 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80
 cmp w2,#1
 b.ne 1f


 mov x10,x3
 mov w11,#8
 mov w12,v3.s[0]
 mov w13,v3.s[1]
 mov w14,v3.s[2]
 mov w15,v3.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v3.s[0],w15
 mov v3.s[1],w14
 mov v3.s[2],w13
 mov v3.s[3],w12

 rev32 v3.16b,v3.16b

 ld1 {v4.4s},[x0]
 eor v4.16b,v4.16b,v3.16b
 st1 {v4.4s},[x1]
 ret
1:

 stp d8,d9,[sp,#-80]!
 stp d10,d11,[sp,#16]
 stp d12,d13,[sp,#32]
 stp d14,d15,[sp,#48]
 stp x29,x30,[sp,#64]
 mov w12,v3.s[0]
 mov w13,v3.s[1]
 mov w14,v3.s[2]
 mov w5,v3.s[3]
.Lctr32_4_blocks_process:
 cmp w2,#4
 b.lt 1f
 dup v4.4s,w12
 dup v5.4s,w13
 dup v6.4s,w14
 mov v7.s[0],w5
 add w5,w5,#1
 mov v7.s[1],w5
 add w5,w5,#1
 mov v7.s[2],w5
 add w5,w5,#1
 mov v7.s[3],w5
 add w5,w5,#1
 cmp w2,#8
 b.ge .Lctr32_8_blocks_process
 bl _vpsm4_ex_enc_4blks
 ld4 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 eor v0.16b,v0.16b,v12.16b
 eor v1.16b,v1.16b,v13.16b
 eor v2.16b,v2.16b,v14.16b
 eor v3.16b,v3.16b,v15.16b
 st4 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 subs w2,w2,#4
 b.ne .Lctr32_4_blocks_process
 b 100f
.Lctr32_8_blocks_process:
 dup v8.4s,w12
 dup v9.4s,w13
 dup v10.4s,w14
 mov v11.s[0],w5
 add w5,w5,#1
 mov v11.s[1],w5
 add w5,w5,#1
 mov v11.s[2],w5
 add w5,w5,#1
 mov v11.s[3],w5
 add w5,w5,#1
 bl _vpsm4_ex_enc_8blks
 ld4 {v12.4s,v13.4s,v14.4s,v15.4s},[x0],#64
 ld4 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 eor v0.16b,v0.16b,v12.16b
 eor v1.16b,v1.16b,v13.16b
 eor v2.16b,v2.16b,v14.16b
 eor v3.16b,v3.16b,v15.16b
 eor v4.16b,v4.16b,v8.16b
 eor v5.16b,v5.16b,v9.16b
 eor v6.16b,v6.16b,v10.16b
 eor v7.16b,v7.16b,v11.16b
 st4 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 st4 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs w2,w2,#8
 b.ne .Lctr32_4_blocks_process
 b 100f
1:
 subs w2,w2,#1
 b.lt 100f
 b.gt 1f
 mov v3.s[0],w12
 mov v3.s[1],w13
 mov v3.s[2],w14
 mov v3.s[3],w5
 mov x10,x3
 mov w11,#8
 mov w12,v3.s[0]
 mov w13,v3.s[1]
 mov w14,v3.s[2]
 mov w15,v3.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v3.s[0],w15
 mov v3.s[1],w14
 mov v3.s[2],w13
 mov v3.s[3],w12

 rev32 v3.16b,v3.16b

 ld1 {v4.4s},[x0]
 eor v4.16b,v4.16b,v3.16b
 st1 {v4.4s},[x1]
 b 100f
1:
 dup v4.4s,w12
 dup v5.4s,w13
 dup v6.4s,w14
 mov v7.s[0],w5
 add w5,w5,#1
 mov v7.s[1],w5
 subs w2,w2,#1
 b.ne 1f
 bl _vpsm4_ex_enc_4blks
 ld4 {v12.s,v13.s,v14.s,v15.s}[0],[x0],#16
 ld4 {v12.s,v13.s,v14.s,v15.s}[1],[x0],#16
 eor v0.16b,v0.16b,v12.16b
 eor v1.16b,v1.16b,v13.16b
 eor v2.16b,v2.16b,v14.16b
 eor v3.16b,v3.16b,v15.16b
 st4 {v0.s,v1.s,v2.s,v3.s}[0],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[1],[x1],#16
 b 100f
1:
 add w5,w5,#1
 mov v7.s[2],w5
 bl _vpsm4_ex_enc_4blks
 ld4 {v12.s,v13.s,v14.s,v15.s}[0],[x0],#16
 ld4 {v12.s,v13.s,v14.s,v15.s}[1],[x0],#16
 ld4 {v12.s,v13.s,v14.s,v15.s}[2],[x0],#16
 eor v0.16b,v0.16b,v12.16b
 eor v1.16b,v1.16b,v13.16b
 eor v2.16b,v2.16b,v14.16b
 eor v3.16b,v3.16b,v15.16b
 st4 {v0.s,v1.s,v2.s,v3.s}[0],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[1],[x1],#16
 st4 {v0.s,v1.s,v2.s,v3.s}[2],[x1],#16
100:
 ldp d10,d11,[sp,#16]
 ldp d12,d13,[sp,#32]
 ldp d14,d15,[sp,#48]
 ldp x29,x30,[sp,#64]
 ldp d8,d9,[sp],#80

 ret
.size vpsm4_ex_ctr32_encrypt_blocks,.-vpsm4_ex_ctr32_encrypt_blocks
.globl vpsm4_ex_xts_encrypt_gb
.type vpsm4_ex_xts_encrypt_gb,%function
.align 5
vpsm4_ex_xts_encrypt_gb:

 stp x15, x16, [sp, #-0x10]!
 stp x17, x18, [sp, #-0x10]!
 stp x19, x20, [sp, #-0x10]!
 stp x21, x22, [sp, #-0x10]!
 stp x23, x24, [sp, #-0x10]!
 stp x25, x26, [sp, #-0x10]!
 stp x27, x28, [sp, #-0x10]!
 stp x29, x30, [sp, #-0x10]!
 stp d8, d9, [sp, #-0x10]!
 stp d10, d11, [sp, #-0x10]!
 stp d12, d13, [sp, #-0x10]!
 stp d14, d15, [sp, #-0x10]!
 mov x26,x3
 mov x27,x4
 mov w28,w6
 ld1 {v16.4s}, [x5]
 mov x3,x27
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80

 rev32 v16.16b,v16.16b

 mov x10,x3
 mov w11,#8
 mov w12,v16.s[0]
 mov w13,v16.s[1]
 mov w14,v16.s[2]
 mov w15,v16.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v16.s[0],w15
 mov v16.s[1],w14
 mov v16.s[2],w13
 mov v16.s[3],w12

 rev32 v16.16b,v16.16b

 mov x3,x26
 and x29,x2,#0x0F

 lsr x2,x2,4
 cmp x2,#1
 b.lt .return_gb

 cmp x29,0


 b.eq .xts_encrypt_blocks_gb




 subs x2,x2,#1
 b.eq .only_2blks_tweak_gb
.xts_encrypt_blocks_gb:
 rbit v16.16b,v16.16b



 mov x12,v16.d[0]
 mov x13,v16.d[1]
 mov w7,0x87
 extr x9,x13,x13,#32
 extr x15,x13,x12,#63
 and w8,w7,w9,asr#31
 eor x14,x8,x12,lsl#1
 mov w7,0x87
 extr x9,x15,x15,#32
 extr x17,x15,x14,#63
 and w8,w7,w9,asr#31
 eor x16,x8,x14,lsl#1
 mov w7,0x87
 extr x9,x17,x17,#32
 extr x19,x17,x16,#63
 and w8,w7,w9,asr#31
 eor x18,x8,x16,lsl#1
 mov w7,0x87
 extr x9,x19,x19,#32
 extr x21,x19,x18,#63
 and w8,w7,w9,asr#31
 eor x20,x8,x18,lsl#1
 mov w7,0x87
 extr x9,x21,x21,#32
 extr x23,x21,x20,#63
 and w8,w7,w9,asr#31
 eor x22,x8,x20,lsl#1
 mov w7,0x87
 extr x9,x23,x23,#32
 extr x25,x23,x22,#63
 and w8,w7,w9,asr#31
 eor x24,x8,x22,lsl#1
 mov w7,0x87
 extr x9,x25,x25,#32
 extr x27,x25,x24,#63
 and w8,w7,w9,asr#31
 eor x26,x8,x24,lsl#1
.Lxts_8_blocks_process_gb:
 cmp x2,#8
 mov v16.d[0],x12
 mov v16.d[1],x13



 mov w7,0x87
 extr x9,x27,x27,#32
 extr x13,x27,x26,#63
 and w8,w7,w9,asr#31
 eor x12,x8,x26,lsl#1
 mov v17.d[0],x14
 mov v17.d[1],x15



 mov w7,0x87
 extr x9,x13,x13,#32
 extr x15,x13,x12,#63
 and w8,w7,w9,asr#31
 eor x14,x8,x12,lsl#1
 mov v18.d[0],x16
 mov v18.d[1],x17



 mov w7,0x87
 extr x9,x15,x15,#32
 extr x17,x15,x14,#63
 and w8,w7,w9,asr#31
 eor x16,x8,x14,lsl#1
 mov v19.d[0],x18
 mov v19.d[1],x19



 mov w7,0x87
 extr x9,x17,x17,#32
 extr x19,x17,x16,#63
 and w8,w7,w9,asr#31
 eor x18,x8,x16,lsl#1
 mov v20.d[0],x20
 mov v20.d[1],x21



 mov w7,0x87
 extr x9,x19,x19,#32
 extr x21,x19,x18,#63
 and w8,w7,w9,asr#31
 eor x20,x8,x18,lsl#1
 mov v21.d[0],x22
 mov v21.d[1],x23



 mov w7,0x87
 extr x9,x21,x21,#32
 extr x23,x21,x20,#63
 and w8,w7,w9,asr#31
 eor x22,x8,x20,lsl#1
 mov v22.d[0],x24
 mov v22.d[1],x25



 mov w7,0x87
 extr x9,x23,x23,#32
 extr x25,x23,x22,#63
 and w8,w7,w9,asr#31
 eor x24,x8,x22,lsl#1
 mov v23.d[0],x26
 mov v23.d[1],x27



 mov w7,0x87
 extr x9,x25,x25,#32
 extr x27,x25,x24,#63
 and w8,w7,w9,asr#31
 eor x26,x8,x24,lsl#1
 b.lt .Lxts_4_blocks_process_gb
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 rbit v16.16b,v16.16b
 rbit v17.16b,v17.16b
 rbit v18.16b,v18.16b
 rbit v19.16b,v19.16b
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b
 eor v7.16b, v7.16b, v19.16b
 ld1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 rbit v20.16b,v20.16b
 rbit v21.16b,v21.16b
 rbit v22.16b,v22.16b
 rbit v23.16b,v23.16b
 eor v8.16b, v8.16b, v20.16b
 eor v9.16b, v9.16b, v21.16b
 eor v10.16b, v10.16b, v22.16b
 eor v11.16b, v11.16b, v23.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b


 rev32 v8.16b,v8.16b


 rev32 v9.16b,v9.16b


 rev32 v10.16b,v10.16b


 rev32 v11.16b,v11.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 zip1 v0.4s,v8.4s,v9.4s
 zip2 v1.4s,v8.4s,v9.4s
 zip1 v2.4s,v10.4s,v11.4s
 zip2 v3.4s,v10.4s,v11.4s
 zip1 v8.2d,v0.2d,v2.2d
 zip2 v9.2d,v0.2d,v2.2d
 zip1 v10.2d,v1.2d,v3.2d
 zip2 v11.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_8blks
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 zip1 v8.4s,v4.4s,v5.4s
 zip2 v9.4s,v4.4s,v5.4s
 zip1 v10.4s,v6.4s,v7.4s
 zip2 v11.4s,v6.4s,v7.4s
 zip1 v4.2d,v8.2d,v10.2d
 zip2 v5.2d,v8.2d,v10.2d
 zip1 v6.2d,v9.2d,v11.2d
 zip2 v7.2d,v9.2d,v11.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 eor v3.16b, v3.16b, v19.16b
 eor v4.16b, v4.16b, v20.16b
 eor v5.16b, v5.16b, v21.16b
 eor v6.16b, v6.16b, v22.16b
 eor v7.16b, v7.16b, v23.16b


 mov v25.16b,v23.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs x2,x2,#8
 b.gt .Lxts_8_blocks_process_gb
 b 100f
.Lxts_4_blocks_process_gb:
 cmp x2,#4
 b.lt 1f
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 rbit v16.16b,v16.16b
 rbit v17.16b,v17.16b
 rbit v18.16b,v18.16b
 rbit v19.16b,v19.16b
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b
 eor v7.16b, v7.16b, v19.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 eor v3.16b, v3.16b, v19.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 sub x2,x2,#4
 mov v16.16b,v20.16b
 mov v17.16b,v21.16b
 mov v18.16b,v22.16b

 mov v25.16b,v19.16b
1:

 cmp x2,#1
 b.lt 100f
 b.gt 1f
 ld1 {v4.4s},[x0],#16
 rbit v16.16b,v16.16b
 eor v4.16b, v4.16b, v16.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v16.16b
 st1 {v4.4s},[x1],#16

 mov v25.16b,v16.16b
 b 100f
1:
 cmp x2,#2
 b.gt 1f
 ld1 {v4.4s,v5.4s},[x0],#32
 rbit v16.16b,v16.16b
 rbit v17.16b,v17.16b
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 st1 {v0.4s,v1.4s},[x1],#32

 mov v25.16b,v17.16b
 b 100f
1:
 ld1 {v4.4s,v5.4s,v6.4s},[x0],#48
 rbit v16.16b,v16.16b
 rbit v17.16b,v17.16b
 rbit v18.16b,v18.16b
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 st1 {v0.4s,v1.4s,v2.4s},[x1],#48

 mov v25.16b,v18.16b
100:
 cmp x29,0
 b.eq .return_gb



.last_2blks_tweak_gb:



 rbit v2.16b,v25.16b
 ldr q0, .Lxts_magic
 shl v17.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v17.16b, v17.16b, v1.16b
 rbit v17.16b,v17.16b
 rbit v2.16b,v17.16b
 ldr q0, .Lxts_magic
 shl v18.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v18.16b, v18.16b, v1.16b
 rbit v18.16b,v18.16b
 b .check_dec_gb




.only_2blks_tweak_gb:
 mov v17.16b,v16.16b



 mov v2.16b,v17.16b
 ldr q0, .Lxts_magic
 shl v18.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v18.16b, v18.16b, v1.16b
 b .check_dec_gb




.check_dec_gb:

 cmp w28,1
 b.eq .prcess_last_2blks_gb
 mov v0.16B,v17.16b
 mov v17.16B,v18.16b
 mov v18.16B,v0.16b

.prcess_last_2blks_gb:






 ld1 {v4.4s},[x0],#16
 eor v4.16b, v4.16b, v17.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v17.16b
 st1 {v4.4s},[x1],#16

 sub x26,x1,16
.loop_gb:
 subs x29,x29,1
 ldrb w7,[x26,x29]
 ldrb w8,[x0,x29]
 strb w8,[x26,x29]
 strb w7,[x1,x29]
 b.gt .loop_gb
 ld1 {v4.4s}, [x26]
 eor v4.16b, v4.16b, v18.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v18.16b
 st1 {v4.4s}, [x26]
.return_gb:
 ldp d14, d15, [sp], #0x10
 ldp d12, d13, [sp], #0x10
 ldp d10, d11, [sp], #0x10
 ldp d8, d9, [sp], #0x10
 ldp x29, x30, [sp], #0x10
 ldp x27, x28, [sp], #0x10
 ldp x25, x26, [sp], #0x10
 ldp x23, x24, [sp], #0x10
 ldp x21, x22, [sp], #0x10
 ldp x19, x20, [sp], #0x10
 ldp x17, x18, [sp], #0x10
 ldp x15, x16, [sp], #0x10

 ret
.size vpsm4_ex_xts_encrypt_gb,.-vpsm4_ex_xts_encrypt_gb
.globl vpsm4_ex_xts_encrypt
.type vpsm4_ex_xts_encrypt,%function
.align 5
vpsm4_ex_xts_encrypt:

 stp x15, x16, [sp, #-0x10]!
 stp x17, x18, [sp, #-0x10]!
 stp x19, x20, [sp, #-0x10]!
 stp x21, x22, [sp, #-0x10]!
 stp x23, x24, [sp, #-0x10]!
 stp x25, x26, [sp, #-0x10]!
 stp x27, x28, [sp, #-0x10]!
 stp x29, x30, [sp, #-0x10]!
 stp d8, d9, [sp, #-0x10]!
 stp d10, d11, [sp, #-0x10]!
 stp d12, d13, [sp, #-0x10]!
 stp d14, d15, [sp, #-0x10]!
 mov x26,x3
 mov x27,x4
 mov w28,w6
 ld1 {v16.4s}, [x5]
 mov x3,x27
 ldr q26, .Lsbox_magic
 ldr q27, .Lsbox_magic+16
 ldr q28, .Lsbox_magic+32
 ldr q29, .Lsbox_magic+48
 ldr q30, .Lsbox_magic+64
 ldr q31, .Lsbox_magic+80

 rev32 v16.16b,v16.16b

 mov x10,x3
 mov w11,#8
 mov w12,v16.s[0]
 mov w13,v16.s[1]
 mov w14,v16.s[2]
 mov w15,v16.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v16.s[0],w15
 mov v16.s[1],w14
 mov v16.s[2],w13
 mov v16.s[3],w12

 rev32 v16.16b,v16.16b

 mov x3,x26
 and x29,x2,#0x0F

 lsr x2,x2,4
 cmp x2,#1
 b.lt .return

 cmp x29,0


 b.eq .xts_encrypt_blocks




 subs x2,x2,#1
 b.eq .only_2blks_tweak
.xts_encrypt_blocks:



 mov x12,v16.d[0]
 mov x13,v16.d[1]
 mov w7,0x87
 extr x9,x13,x13,#32
 extr x15,x13,x12,#63
 and w8,w7,w9,asr#31
 eor x14,x8,x12,lsl#1
 mov w7,0x87
 extr x9,x15,x15,#32
 extr x17,x15,x14,#63
 and w8,w7,w9,asr#31
 eor x16,x8,x14,lsl#1
 mov w7,0x87
 extr x9,x17,x17,#32
 extr x19,x17,x16,#63
 and w8,w7,w9,asr#31
 eor x18,x8,x16,lsl#1
 mov w7,0x87
 extr x9,x19,x19,#32
 extr x21,x19,x18,#63
 and w8,w7,w9,asr#31
 eor x20,x8,x18,lsl#1
 mov w7,0x87
 extr x9,x21,x21,#32
 extr x23,x21,x20,#63
 and w8,w7,w9,asr#31
 eor x22,x8,x20,lsl#1
 mov w7,0x87
 extr x9,x23,x23,#32
 extr x25,x23,x22,#63
 and w8,w7,w9,asr#31
 eor x24,x8,x22,lsl#1
 mov w7,0x87
 extr x9,x25,x25,#32
 extr x27,x25,x24,#63
 and w8,w7,w9,asr#31
 eor x26,x8,x24,lsl#1
.Lxts_8_blocks_process:
 cmp x2,#8
 mov v16.d[0],x12
 mov v16.d[1],x13



 mov w7,0x87
 extr x9,x27,x27,#32
 extr x13,x27,x26,#63
 and w8,w7,w9,asr#31
 eor x12,x8,x26,lsl#1
 mov v17.d[0],x14
 mov v17.d[1],x15



 mov w7,0x87
 extr x9,x13,x13,#32
 extr x15,x13,x12,#63
 and w8,w7,w9,asr#31
 eor x14,x8,x12,lsl#1
 mov v18.d[0],x16
 mov v18.d[1],x17



 mov w7,0x87
 extr x9,x15,x15,#32
 extr x17,x15,x14,#63
 and w8,w7,w9,asr#31
 eor x16,x8,x14,lsl#1
 mov v19.d[0],x18
 mov v19.d[1],x19



 mov w7,0x87
 extr x9,x17,x17,#32
 extr x19,x17,x16,#63
 and w8,w7,w9,asr#31
 eor x18,x8,x16,lsl#1
 mov v20.d[0],x20
 mov v20.d[1],x21



 mov w7,0x87
 extr x9,x19,x19,#32
 extr x21,x19,x18,#63
 and w8,w7,w9,asr#31
 eor x20,x8,x18,lsl#1
 mov v21.d[0],x22
 mov v21.d[1],x23



 mov w7,0x87
 extr x9,x21,x21,#32
 extr x23,x21,x20,#63
 and w8,w7,w9,asr#31
 eor x22,x8,x20,lsl#1
 mov v22.d[0],x24
 mov v22.d[1],x25



 mov w7,0x87
 extr x9,x23,x23,#32
 extr x25,x23,x22,#63
 and w8,w7,w9,asr#31
 eor x24,x8,x22,lsl#1
 mov v23.d[0],x26
 mov v23.d[1],x27



 mov w7,0x87
 extr x9,x25,x25,#32
 extr x27,x25,x24,#63
 and w8,w7,w9,asr#31
 eor x26,x8,x24,lsl#1
 b.lt .Lxts_4_blocks_process
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b
 eor v7.16b, v7.16b, v19.16b
 ld1 {v8.4s,v9.4s,v10.4s,v11.4s},[x0],#64
 eor v8.16b, v8.16b, v20.16b
 eor v9.16b, v9.16b, v21.16b
 eor v10.16b, v10.16b, v22.16b
 eor v11.16b, v11.16b, v23.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b


 rev32 v8.16b,v8.16b


 rev32 v9.16b,v9.16b


 rev32 v10.16b,v10.16b


 rev32 v11.16b,v11.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 zip1 v0.4s,v8.4s,v9.4s
 zip2 v1.4s,v8.4s,v9.4s
 zip1 v2.4s,v10.4s,v11.4s
 zip2 v3.4s,v10.4s,v11.4s
 zip1 v8.2d,v0.2d,v2.2d
 zip2 v9.2d,v0.2d,v2.2d
 zip1 v10.2d,v1.2d,v3.2d
 zip2 v11.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_8blks
 zip1 v8.4s,v0.4s,v1.4s
 zip2 v9.4s,v0.4s,v1.4s
 zip1 v10.4s,v2.4s,v3.4s
 zip2 v11.4s,v2.4s,v3.4s
 zip1 v0.2d,v8.2d,v10.2d
 zip2 v1.2d,v8.2d,v10.2d
 zip1 v2.2d,v9.2d,v11.2d
 zip2 v3.2d,v9.2d,v11.2d
 zip1 v8.4s,v4.4s,v5.4s
 zip2 v9.4s,v4.4s,v5.4s
 zip1 v10.4s,v6.4s,v7.4s
 zip2 v11.4s,v6.4s,v7.4s
 zip1 v4.2d,v8.2d,v10.2d
 zip2 v5.2d,v8.2d,v10.2d
 zip1 v6.2d,v9.2d,v11.2d
 zip2 v7.2d,v9.2d,v11.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 eor v3.16b, v3.16b, v19.16b
 eor v4.16b, v4.16b, v20.16b
 eor v5.16b, v5.16b, v21.16b
 eor v6.16b, v6.16b, v22.16b
 eor v7.16b, v7.16b, v23.16b


 mov v25.16b,v23.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 st1 {v4.4s,v5.4s,v6.4s,v7.4s},[x1],#64
 subs x2,x2,#8
 b.gt .Lxts_8_blocks_process
 b 100f
.Lxts_4_blocks_process:
 cmp x2,#4
 b.lt 1f
 ld1 {v4.4s,v5.4s,v6.4s,v7.4s},[x0],#64
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b
 eor v7.16b, v7.16b, v19.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b


 rev32 v7.16b,v7.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 eor v3.16b, v3.16b, v19.16b
 st1 {v0.4s,v1.4s,v2.4s,v3.4s},[x1],#64
 sub x2,x2,#4
 mov v16.16b,v20.16b
 mov v17.16b,v21.16b
 mov v18.16b,v22.16b

 mov v25.16b,v19.16b
1:

 cmp x2,#1
 b.lt 100f
 b.gt 1f
 ld1 {v4.4s},[x0],#16
 eor v4.16b, v4.16b, v16.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v16.16b
 st1 {v4.4s},[x1],#16

 mov v25.16b,v16.16b
 b 100f
1:
 cmp x2,#2
 b.gt 1f
 ld1 {v4.4s,v5.4s},[x0],#32
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 st1 {v0.4s,v1.4s},[x1],#32

 mov v25.16b,v17.16b
 b 100f
1:
 ld1 {v4.4s,v5.4s,v6.4s},[x0],#48
 eor v4.16b, v4.16b, v16.16b
 eor v5.16b, v5.16b, v17.16b
 eor v6.16b, v6.16b, v18.16b

 rev32 v4.16b,v4.16b


 rev32 v5.16b,v5.16b


 rev32 v6.16b,v6.16b

 zip1 v0.4s,v4.4s,v5.4s
 zip2 v1.4s,v4.4s,v5.4s
 zip1 v2.4s,v6.4s,v7.4s
 zip2 v3.4s,v6.4s,v7.4s
 zip1 v4.2d,v0.2d,v2.2d
 zip2 v5.2d,v0.2d,v2.2d
 zip1 v6.2d,v1.2d,v3.2d
 zip2 v7.2d,v1.2d,v3.2d
 bl _vpsm4_ex_enc_4blks
 zip1 v4.4s,v0.4s,v1.4s
 zip2 v5.4s,v0.4s,v1.4s
 zip1 v6.4s,v2.4s,v3.4s
 zip2 v7.4s,v2.4s,v3.4s
 zip1 v0.2d,v4.2d,v6.2d
 zip2 v1.2d,v4.2d,v6.2d
 zip1 v2.2d,v5.2d,v7.2d
 zip2 v3.2d,v5.2d,v7.2d
 eor v0.16b, v0.16b, v16.16b
 eor v1.16b, v1.16b, v17.16b
 eor v2.16b, v2.16b, v18.16b
 st1 {v0.4s,v1.4s,v2.4s},[x1],#48

 mov v25.16b,v18.16b
100:
 cmp x29,0
 b.eq .return



.last_2blks_tweak:



 mov v2.16b,v25.16b
 ldr q0, .Lxts_magic
 shl v17.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v17.16b, v17.16b, v1.16b
 mov v2.16b,v17.16b
 ldr q0, .Lxts_magic
 shl v18.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v18.16b, v18.16b, v1.16b
 b .check_dec




.only_2blks_tweak:
 mov v17.16b,v16.16b



 mov v2.16b,v17.16b
 ldr q0, .Lxts_magic
 shl v18.16b, v2.16b, #1
 ext v1.16b, v2.16b, v2.16b,#15
 ushr v1.16b, v1.16b, #7
 mul v1.16b, v1.16b, v0.16b
 eor v18.16b, v18.16b, v1.16b
 b .check_dec




.check_dec:

 cmp w28,1
 b.eq .prcess_last_2blks
 mov v0.16B,v17.16b
 mov v17.16B,v18.16b
 mov v18.16B,v0.16b

.prcess_last_2blks:






 ld1 {v4.4s},[x0],#16
 eor v4.16b, v4.16b, v17.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v17.16b
 st1 {v4.4s},[x1],#16

 sub x26,x1,16
.loop:
 subs x29,x29,1
 ldrb w7,[x26,x29]
 ldrb w8,[x0,x29]
 strb w8,[x26,x29]
 strb w7,[x1,x29]
 b.gt .loop
 ld1 {v4.4s}, [x26]
 eor v4.16b, v4.16b, v18.16b

 rev32 v4.16b,v4.16b

 mov x10,x3
 mov w11,#8
 mov w12,v4.s[0]
 mov w13,v4.s[1]
 mov w14,v4.s[2]
 mov w15,v4.s[3]
10:
 ldp w7,w8,[x10],8

 eor w6,w14,w15
 eor w9,w7,w13
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w12,w12,w6

 eor w6,w14,w15
 eor w9,w12,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 ldp w7,w8,[x10],8
 eor w13,w13,w6

 eor w6,w12,w13
 eor w9,w7,w15
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w14,w14,w6

 eor w6,w12,w13
 eor w9,w14,w8
 eor w6,w6,w9
 mov v3.s[0],w6

 tbl v0.16b, {v3.16b}, v26.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v28.16b}, v0.16b
 tbl v2.16b, {v27.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b
 eor v1.16b, v1.16b, v1.16b
 aese v0.16b,v1.16b
 ushr v2.16b, v0.16b, 4
 and v0.16b, v0.16b, v31.16b
 tbl v0.16b, {v30.16b}, v0.16b
 tbl v2.16b, {v29.16b}, v2.16b
 eor v0.16b, v0.16b, v2.16b

 mov w7,v0.s[0]
 eor w6,w7,w7,ror #32-2
 eor w6,w6,w7,ror #32-10
 eor w6,w6,w7,ror #32-18
 eor w6,w6,w7,ror #32-24
 eor w15,w15,w6
 subs w11,w11,#1
 b.ne 10b
 mov v4.s[0],w15
 mov v4.s[1],w14
 mov v4.s[2],w13
 mov v4.s[3],w12

 rev32 v4.16b,v4.16b

 eor v4.16b, v4.16b, v18.16b
 st1 {v4.4s}, [x26]
.return:
 ldp d14, d15, [sp], #0x10
 ldp d12, d13, [sp], #0x10
 ldp d10, d11, [sp], #0x10
 ldp d8, d9, [sp], #0x10
 ldp x29, x30, [sp], #0x10
 ldp x27, x28, [sp], #0x10
 ldp x25, x26, [sp], #0x10
 ldp x23, x24, [sp], #0x10
 ldp x21, x22, [sp], #0x10
 ldp x19, x20, [sp], #0x10
 ldp x17, x18, [sp], #0x10
 ldp x15, x16, [sp], #0x10

 ret
.size vpsm4_ex_xts_encrypt,.-vpsm4_ex_xts_encrypt
