import bcc

code='''
BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("Tail-call\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program\n");
    prog_array.call(ctx, 2);
    return 0;
}
'''

b = BPF(text=code)
tail_fn = b.load_func("tail_call", BPF.KPROBE)
prog_array = b.get_table("prog_array")
prog_array[c_int(2)] = c_int(tail_fn.fd)
b.attach_kprobe(event="some_kprobe_event", fn_name="do_tail_call")
