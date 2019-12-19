from bcc import BPF

code='''
BPF_PROG_ARRAY(prog_array, 10);

int ingress_path(void *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;


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
DEVICE='eno2'
ingress_fn = b.load_func("ingress_path", bpf.XDP)
b.attach_xdp(DEVICE, ingress_fn, 0)


b.remove_xdp(DEVICE)
