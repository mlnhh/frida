using GLib;
using Gum;

extern void** Stage_instance;
extern void* StringTable_getMovieClip(string file, string name);
extern void DisplayObject_setXY(void* obj, float x, float y);
extern void DisplayObject_setScale(void* obj, float x, float y);
extern void Stage_addChild(void* stage, void* child);

namespace Frida.Gadget {

    class SetArg0To0Listener : Object, InvocationListener {
        public void on_enter(InvocationContext context) {
            Arm64CpuContext* cpu = (Arm64CpuContext*) context.cpu_context;
            cpu->x[0] = 0;
        }
        public void on_leave(InvocationContext context) {}
    }

    class SetArg0To1Listener : Object, InvocationListener {
        public void on_enter(InvocationContext context) {
            Arm64CpuContext* cpu = (Arm64CpuContext*) context.cpu_context;
            cpu->x[0] = 1;
        }
        public void on_leave(InvocationContext context) {}
    }

    class MenuListener : Object, InvocationListener {
        private FridaGadget gadget;
        public MenuListener(FridaGadget gadget) {
            this.gadget = gadget;
        }
        public void on_enter(InvocationContext context) {
            gadget.openNLBRMenu();
        }
        public void on_leave(InvocationContext context) {}
    }

    public class FridaGadget : Object {
        private static FridaGadget instance;

        construct {
            var laser = Gum.Process.find_module_by_name("laser");
            if (laser == null) return;
            
            Address base_addr = laser.range.base_address;
            var interceptor = Interceptor.obtain();
            var arg0_0 = new SetArg0To0Listener();
            var arg0_1 = new SetArg0To1Listener();

            patch_ret((void*)(base_addr + 0x101010da4));
            patch_ret((void*)(base_addr + 0x10101d0d4));
            patch_ret((void*)(base_addr + 0x100f10e38));
            patch_ret((void*)(base_addr + 0x100a8991c));

            interceptor.attach((void*)(base_addr + 0x101016ba8), arg0_0);
            interceptor.attach((void*)(base_addr + 0x1011e1f54), arg0_0);
            interceptor.attach((void*)(base_addr + 0x1011e0170), arg0_0);
            interceptor.attach((void*)(base_addr + 0x1010ad210), arg0_1);
            interceptor.attach((void*)(base_addr + 0x1010170dc), arg0_0);
            interceptor.attach((void*)(base_addr + 0x1011e214c), arg0_0);
            interceptor.attach((void*)(base_addr + 0x10101bdfc), arg0_0);
            interceptor.attach((void*)(base_addr + 0x10101e510), arg0_0);
            interceptor.attach((void*)(base_addr + 0x10101bdfc), arg0_0); 
            interceptor.attach((void*)(base_addr + 0x1010ac84c), arg0_0);
            interceptor.attach((void*)(base_addr + 0x10101ab4c), arg0_0);
            interceptor.attach((void*)(base_addr + 0x1011dfb24), arg0_0);

            void* stage = *Stage_instance; 
            var menuBtn = StringTable_getMovieClip("sc/ui.sc", "menu_button");
            DisplayObject_setXY(menuBtn, 40.0f, 40.0f);
            DisplayObject_setScale(menuBtn, 1.35f, 1.35f);
            Stage_addChild(stage, menuBtn);

            void* vtable_addr = *((void**) menuBtn);
            void* btnHandler = *((void**) ((uint8*) vtable_addr + 0x350));
            interceptor.attach(btnHandler, new MenuListener(this));
        }

        private void patch_ret(void* address) {
            Gum.Memory.patch_code(address, 4, (mem) => {
                var writer = new Arm64Writer(mem);
                writer.put_ret();
                writer.flush();
            });
        }

        public void openNLBRMenu() {}

        // Entry point for the C code
        public static void load(MemoryRange? mapped_range, string? config_data, int* result) {
            if (instance == null) {
                instance = new FridaGadget();
            }
        }

        public static void unload() {
            instance = null;
        }
        
        public static void environment_init() {
            // Placeholder for C code requirement
        }
        
        public static void on_pending_thread_garbage(void* data) {
            // Fixes the garbage handler error
        }
    }
}
