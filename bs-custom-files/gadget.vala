using GLib;
using Gum;

namespace Frida.Gadget {
    [CCode (cname = "frida_gadget_environment_init")]
    public extern void environment_init();

    [CCode (cname = "frida_gadget_load")]
    public void load (MemoryRange? mapped_range, string? config_data, int* result) {
        FridaGadget.boot();
    }

    [CCode (cname = "frida_gadget_unload")]
    public void unload() {}

    class FridaGadget : Object {
        private static FridaGadget instance;

        public static void boot() {
            if (instance == null) {
                instance = new FridaGadget();
            }
        }

        construct {
            // Nothing heavy here - all work is moved to load.lebronjs with lobby detection
        }
    }
}
