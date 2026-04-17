using GLib;
using Gum;

namespace Frida.Gadget {

    [CCode (cname = "frida_gadget_environment_init")]
    public extern void environment_init ();

    [CCode (cname = "frida_gadget_load")]
    public void load (MemoryRange? mapped_range, string? config_data, int* result) {
        FridaGadget.boot ();
    }

    [CCode (cname = "frida_gadget_unload")]
    public void unload () {}

    class FridaGadget : Object {

        private static FridaGadget instance;

        public static void boot () {
            if (instance == null)
                instance = new FridaGadget ();
        }

        construct {
            /*
             * Apply stealth AFTER environment_init has already run (it is
             * called from frida_on_load before frida_gadget_load, so by the
             * time we reach this constructor the runtime is fully up).
             * We call it unconditionally here – no swallowed errors.
             */
            frida_gadget_environment_ensure_debugger_breakpoints_only ();
        }
    }

    [CCode (cname = "frida_gadget_environment_ensure_debugger_breakpoints_only")]
    public extern void frida_gadget_environment_ensure_debugger_breakpoints_only ();
}
