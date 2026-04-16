using GLib;
using Gum;

namespace Frida.Gadget {

    // This tells Vala that the function is defined in the Frida C-glue
    // so it won't try to generate a duplicate definition.
    [CCode (cname = "frida_gadget_environment_init")]
    public extern void environment_init ();

    [CCode (cname = "frida_gadget_load")]
    public void load (MemoryRange? mapped_range, string? config_data, int* result) {
        FridaGadget.boot ();
    }

    [CCode (cname = "frida_gadget_unload")]
    public void unload () {
    }

    [CCode (cname = "_frida_gadget_on_pending_thread_garbage")]
    public void on_pending_thread_garbage (void* data) {
    }

    class SetArg0To0Listener : Object, InvocationListener {
        public void on_enter (InvocationContext context) {
            Arm64CpuContext* cpu = (Arm64CpuContext*) context.cpu_context;
            cpu->x[0] = 0;
        }
        public void on_leave (InvocationContext context) {}
    }

    class SetArg0To1Listener : Object, InvocationListener {
        public void on_enter (InvocationContext context) {
            Arm64CpuContext* cpu = (Arm64CpuContext*) context.cpu_context;
            cpu->x[0] = 1;
        }
        public void on_leave (InvocationContext context) {}
    }

    public class FridaGadget : Object {
        private static FridaGadget instance;

        public static void boot () {
            if (instance == null) {
                instance = new FridaGadget ();
            }
        }

        construct {
            var laser = Gum.Process.find_module_by_name ("laser");
            if (laser == null) return;
            
            Address base_addr = laser.range.base_address;
            var interceptor = Interceptor.obtain ();
            var arg0_0 = new SetArg0To0Listener ();
            var arg0_1 = new SetArg0To1Listener ();

            patch_ret ((void*) (base_addr + 0x101010da4));
            patch_ret ((void*) (base_addr + 0x10101d0d4));
            patch_ret ((void*) (base_addr + 0x100f10e38));
            patch_ret ((void*) (base_addr + 0x100a8991c));

            interceptor.attach ((void*) (base_addr + 0x101016ba8), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x1011e1f54), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x1011e0170), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x1010ad210), arg0_1);
            interceptor.attach ((void*) (base_addr + 0x1010170dc), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x1011e214c), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x10101bdfc), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x10101e510), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x10101bdfc), arg0_0); 
            interceptor.attach ((void*) (base_addr + 0x1010ac84c), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x10101ab4c), arg0_0);
            interceptor.attach ((void*) (base_addr + 0x1011dfb24), arg0_0);
        }

        private void patch_ret (void* address) {
            Gum.Memory.patch_code (address, 4, (mem) => {
                var writer = new Arm64Writer (mem);
                writer.put_ret ();
                writer.flush ();
            });
        }
    }
}
