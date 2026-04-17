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
            // Basic stealth - prevent breakpoint stealing (BSRE style)
            try {
                frida_gadget_environment_ensure_debugger_breakpoints_only();
            } catch (Error e) {}
        }
    }

    // Declare the stealth function from gadget-darwin.m
    [CCode (cname = "frida_gadget_environment_ensure_debugger_breakpoints_only")]
    public extern void frida_gadget_environment_ensure_debugger_breakpoints_only ();
}
