
Unwinding the stack frame
=========================

Basic principle of how to read a row of register rules:
* At any point the CFARule says 'the CFA addr is regN + offset'.
* i.e on program entry (reg=32, offset=2) means CFA = SP + 2
* after a push, (reg=32, offset=3) means CFA = SP + 3
* after switching to the frame pointer 'Y', then CFA = Y + 16 or Y + 56.
* The CFA is where the SP will point after the 'ret' completes and the return addr is popped.
* r36 is the virtual Link Register (return addr register).
* `36: RegisterRule(OFFSET, -1)` means "r36 (return addr) is at address CFA + -1"
* The register rules are all written relative to the *CFA*.
* The CFA must be calculated at any point by looking at the CFARule and taking its offset relative to
the named register.

An issue with gcc-generated `.debug_frame` info is that it only generates CFA rules for the prologue.
Therefore, if a breakpoint interrupt fires while a method is in its epilogue, we will not be able
to detect (a) that the epilogue has begun or (b) how to recover the remaining register unwind state
or the top of the stack frame. The last CFA rule issued at the end of the prologue has the
implication of being valid through the `ret` or `reti` instruction, when this is not actually the
case. Not entirely sure how to detect or handle this case.

General example of stack unwinding:
------------------------------------

The most complicated example is `NewhavenLcd0440::_scrollScreen()`, which combines the simple
SP-relative rule with a switch to using the frame pointer.

```
00000cb8 <_ZN15NewhavenLcd044013_scrollScreenEv>:
     cb8:       6f 92           push    r6
     cba:       7f 92           push    r7
     cbc:       8f 92           push    r8
     cbe:       9f 92           push    r9
     cc0:       af 92           push    r10
     cc2:       bf 92           push    r11
     cc4:       cf 92           push    r12
     cc6:       df 92           push    r13
     cc8:       ef 92           push    r14
     cca:       ff 92           push    r15
     ccc:       0f 93           push    r16
     cce:       1f 93           push    r17
     cd0:       cf 93           push    r28
     cd2:       df 93           push    r29
     cd4:       cd b7           in      r28, 0x3d       ; 61
     cd6:       de b7           in      r29, 0x3e       ; 62 <-- frameptr active here
     cd8:       a8 97           sbiw    r28, 0x28       ; 40
     cda:       0f b6           in      r0, 0x3f        ; 63


# This is how prologue rules generally start, being SP- (r32)-relative and adding one
# register rule per instruction throughout the prologue as we push successive registers.
# Note that the rule set is valid for the moment immediately *before* the instruction at
# the specified PC is executed. e.g., the 0xcb8 rule is valid as we are entering the function.
# After the 0xcb8 instruction runs, we are in the state marked for $PC=0x0cba.
PC: 0cb8 {'cfa': CFARule(reg=32, offset=2, expr=None), 36: RegisterRule(OFFSET, -1)}
PC: 0cba {'cfa': CFARule(reg=32, offset=3, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2)}
PC: 0cbc {'cfa': CFARule(reg=32, offset=4, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3)}
PC: 0cbe {'cfa': CFARule(reg=32, offset=5, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4)}
PC: 0cc0 {'cfa': CFARule(reg=32, offset=6, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5)}
PC: 0cc2 {'cfa': CFARule(reg=32, offset=7, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5), 10: RegisterRule(OFFSET, -6)}
PC: 0cc4 {'cfa': CFARule(reg=32, offset=8, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5), 10: RegisterRule(OFFSET, -6), 11: RegisterRule(OFFSET, -7)}

... more prologue like this...

PC: 0cd4 {'cfa': CFARule(reg=32, offset=16, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5), 10: RegisterRule(OFFSET, -6), 11: RegisterRule(OFFSET, -7), 12: RegisterRule(OFFSET, -8), 13: RegisterRule(OFFSET, -9), 14: RegisterRule(OFFSET, -10), 15: RegisterRule(OFFSET, -11), 16: RegisterRule(OFFSET, -12), 17: RegisterRule(OFFSET, -13), 28: RegisterRule(OFFSET, -14), 29: RegisterRule(OFFSET, -15)}

#### Switch to r29:r28 'Y' as frame pointer now active:

PC: 0cd8 {'cfa': CFARule(reg=28, offset=16, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5), 10: RegisterRule(OFFSET, -6), 11: RegisterRule(OFFSET, -7), 12: RegisterRule(OFFSET, -8), 13: RegisterRule(OFFSET, -9), 14: RegisterRule(OFFSET, -10), 15: RegisterRule(OFFSET, -11), 16: RegisterRule(OFFSET, -12), 17: RegisterRule(OFFSET, -13), 28: RegisterRule(OFFSET, -14), 29: RegisterRule(OFFSET, -15)}

#### SBIW of 40 switches offset from +16 to +56:

PC: 0cda {'cfa': CFARule(reg=28, offset=56, expr=None), 36: RegisterRule(OFFSET, -1), 6: RegisterRule(OFFSET, -2), 7: RegisterRule(OFFSET, -3), 8: RegisterRule(OFFSET, -4), 9: RegisterRule(OFFSET, -5), 10: RegisterRule(OFFSET, -6), 11: RegisterRule(OFFSET, -7), 12: RegisterRule(OFFSET, -8), 13: RegisterRule(OFFSET, -9), 14: RegisterRule(OFFSET, -10), 15: RegisterRule(OFFSET, -11), 16: RegisterRule(OFFSET, -12), 17: RegisterRule(OFFSET, -13), 28: RegisterRule(OFFSET, -14), 29: RegisterRule(OFFSET, -15)}
```


Bug in ISR stack frame unwind info from gcc
-------------------------------------------

There is a bug in GCC with stack unwind info in ISRs that we will need to work around; since the
debugger's ^C breakpoint is triggered by an ISR, it will be an immediate blocker to proper
stack unwinding.

The problem is in all non-naked ISRs that save SREG as part of their prologue. See e.g. __vector_10
at PC=0x19dc:

```
  19dc:       1f 92           push    r1
  19de:       0f 92           push    r0
  19e0:       0f b6           in      r0, 0x3f        ; 63
  19e2:       0f 92           push    r0 # This 2-instruction `in r0, 0x3f; push r0` clause
                                         # reads SREG into r0 then pushes to the stack, but
                                         # in addition to not marking SREG as pushed at this
                                         # offset, we don't even record that there was a push.
                                         # So, we need to detect `0f b6 0f 92` in the prologue
                                         # and adjust *all* register offsets below this PC in
                                         # the unwind rules by 1 byte.
  19e4:       11 24           eor     r1, r1
  19e6:       8f 93           push    r24
```

I believe the bug is in `gcc/config/avr/avr.c` at lines 1946--47:
```
1946           /* ??? There's no dwarf2 column reserved for SREG.  */
1947           emit_push_sfr (sreg_rtx, false, false /* clr */, AVR_TMP_REGNO);
```

I think the 2nd argument may need to be `true` to set `frame_related_p=true` (which
marks the instruction as `RTX_FRAME_RELATED_P(insn)=1`.

ISR bug demo
---------------

```
// Disassembly of __vector_17() via `avr-objdump -S`:

ISR(TIMER1_COMPA_vect) {
  ce:   1f 92           push    r1
  d0:   0f 92           push    r0
  d2:   0f b6           in      r0, 0x3f        ; 63
  d4:   0f 92           push    r0
  d6:   11 24           eor     r1, r1
  d8:   8f 93           push    r24
  x++; // may set carry/overflow flags and affect SREG, forcing it to be pushed.
  da:   80 91 00 01     lds     r24, 0x0100     ; 0x800100 <_edata>
  de:   8f 5f           subi    r24, 0xFF       ; 255
  e0:   80 93 00 01     sts     0x0100, r24     ; 0x800100 <_edata>
}
  e4:   8f 91           pop     r24
  e6:   0f 90           pop     r0
  e8:   0f be           out     0x3f, r0        ; 63
  ea:   0f 90           pop     r0
  ec:   1f 90           pop     r1
  ee:   18 95           reti

// .debug_frame processed state from pyelftools:

(Header for CIE:) length': 16, 'CIE_id': 4294967295, 'version': 1, 'augmentation': b'',
'code_alignment_factor': 2, 'data_alignment_factor': -1, 'return_address_register': 36})

* FDE for __vector_17() starting at $PC=0x00ce:

PC: 00ce {'cfa': CFARule(reg=32, offset=2, expr=None), 36: RegisterRule(OFFSET, -1)}
PC: 00d0 {'cfa': CFARule(reg=32, offset=3, expr=None), 36: RegisterRule(OFFSET, -1), 1: RegisterRule(OFFSET, -2)}
PC: 00d2 {'cfa': CFARule(reg=32, offset=4, expr=None), 36: RegisterRule(OFFSET, -1), 1: RegisterRule(OFFSET, -2), 0: RegisterRule(OFFSET, -3)}

<-- we *should* see a RegisterRule for SREG here valid after $PC=00d4h.

PC: 00da {'cfa': CFARule(reg=32, offset=5, expr=None), 36: RegisterRule(OFFSET, -1), 1: RegisterRule(OFFSET, -2), 0: RegisterRule(OFFSET, -3), 24: RegisterRule(OFFSET, -4)}

^-- Even that notwithstanding, the 'push' means the CFARule offset is now 1 too few, and the
subsequent RegisterRule offset for r24 makes it look snug against r0, ignoring the
intervening push; CFARule offset should = 6 and r24's rule should have OFFSET=-5.
```

