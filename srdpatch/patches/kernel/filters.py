"""The inlined bitstr_test(mask, idx) that both syscall filter checks share.

There are two copies in the image and neither accessor can be found by its own
code -- the two have identical prologues -- so each is taken as the call target
at its own filter check. These patterns are what tell the two checks apart.
"""
from ... import arm64 as A

BITSTR_TEST = [
    A.asr_imm_w(shift=3),            # asr  w9, wIDX, #3
    A.ldrb_reg_sxtw(),               # ldrb w9, [x0, w9, sxtw]
    A.and_imm_w(imm=7),              # and  w10, wIDX, #7
    A.lsr_reg_w(),                   # lsr  w9, w9, w10
    A.tbnz(bit=0),                   # tbnz w9, #0, ALLOW
]
KOBJ_FILTER = [A.cmn_imm(imm=1), A.bcc('eq')] + BITSTR_TEST + [
    A.ldr_x(),                       # ldr x8, [x8, #off]  mac_task_kobj_msg_evaluate
    A.cbz(sf=1),                     # cbz x8, ALLOW
]
TRAP_FILTER = [A.bl(), A.cbz(sf=1)] + BITSTR_TEST


def kobj_filter_site(im):
    return im.find_one(KOBJ_FILTER, what="ipc_kobject_server's filter check")


