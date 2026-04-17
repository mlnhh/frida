#if defined (HAVE_TVOS) || defined (HAVE_WATCHOS)
# include <Availability.h>
# undef __TVOS_PROHIBITED
# define __TVOS_PROHIBITED
# undef __WATCHOS_PROHIBITED
# define __WATCHOS_PROHIBITED
#endif

#include "frida-gadget.h"
#include "frida-base.h"
#import <Foundation/Foundation.h>
#include <gum/gumdarwin.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <gum/gum.h>
#include <gum/gumprocess.h>

void frida_gadget_environment_init (void);
void frida_gadget_environment_ensure_debugger_breakpoints_only (void);

static void apply_ret_patch(gpointer mem, gpointer user_data) {
    guint32 *code = (guint32 *)mem;
    *code = 0xd65f03c0;
}

static void apply_mov1_ret_patch(gpointer mem, gpointer user_data) {
    guint32 *code = (guint32 *)mem;
    code[0] = 0x52800020;
    code[1] = 0xd65f03c0;
}

static void execute_native_anticheat_kills(void) {
    GumAddress base = gum_module_find_base_address("laser");
    if (base == 0) return;

    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x101010da4), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x1011e214c), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x1011e1f54), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x1011dfb24), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x100004440), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x1011e0170), 4, apply_ret_patch, NULL);
    gum_memory_patch_code(GSIZE_TO_POINTER(base + 0x1010ad210), 8, apply_mov1_ret_patch, NULL);
}

static gchar *
frida_resolve_gadget_dir (void)
{
    Dl_info info;
    if (dladdr ((void *) frida_resolve_gadget_dir, &info) == 0 || info.dli_fname == NULL)
        return NULL;

    NSString *dylib_path = [NSString stringWithUTF8String:info.dli_fname];
    NSString *dir        = [dylib_path stringByDeletingLastPathComponent];
    return g_strdup ([dir UTF8String]);
}

__attribute__ ((constructor)) static void
frida_on_load (int argc, const char * argv[], const char * envp[], const char * apple[], int * result)
{
    frida_gadget_environment_init ();
    
    execute_native_anticheat_kills();
    
    frida_gadget_environment_ensure_debugger_breakpoints_only();

    gboolean found_range;
    GumMemoryRange range;
    gchar * config_data = NULL;

    extern void frida_parse_apple_parameters (const char * apple[], gboolean * found_range, GumMemoryRange * range, gchar ** config_data);
    frida_parse_apple_parameters (apple, &found_range, &range, &config_data);

    gchar * gadget_dir = frida_resolve_gadget_dir ();
    gchar * script_path = (gadget_dir != NULL)
        ? g_strdup_printf ("%s/ss/load.lebronjs", gadget_dir)
        : g_strdup ("ss/load.lebronjs");
    g_free (gadget_dir);

    gchar * json = g_strdup_printf (
        "{\n"
        "  \"interaction\": {\n"
        "    \"type\": \"script\",\n"
        "    \"path\": \"%s\",\n"
        "    \"on_change\": \"ignore\"\n"
        "  }\n"
        "}", script_path);
    g_free (script_path);

    if (config_data != NULL)
        g_free (config_data);
    config_data = json;

    frida_gadget_load (found_range ? &range : NULL, config_data, result);

    g_free (config_data);
}

__attribute__ ((destructor)) static void
frida_on_unload (void)
{
    frida_gadget_unload ();
}

void
frida_gadget_environment_detect_darwin_location_fields (GumAddress our_address, gchar ** executable_name, gchar ** our_path, GumMemoryRange ** our_range)
{
    mach_port_t task = mach_task_self ();
    GumDarwinModuleResolver *resolver = gum_darwin_module_resolver_new (task, NULL);
    if (resolver == NULL) return;

    GPtrArray *modules;
    gum_darwin_module_resolver_fetch_modules (resolver, &modules, NULL);

    for (guint i = 0; i < modules->len; i++) {
        GumModule *module = g_ptr_array_index (modules, i);
        const GumMemoryRange *mrange = gum_module_get_range (module);

        if (*executable_name == NULL) {
            gum_mach_header_t *header = GSIZE_TO_POINTER (mrange->base_address);
            if (header->filetype == MH_EXECUTE)
                *executable_name = g_strdup (gum_module_get_name (module));
        }

        if (our_address >= mrange->base_address && our_address < mrange->base_address + mrange->size) {
            if (*our_path == NULL)
                *our_path = g_strdup (gum_module_get_path (module));
            if (*our_range == NULL)
                *our_range = gum_memory_range_copy (mrange);
        }

        if (*executable_name != NULL && *our_path != NULL && *our_range != NULL) break;
    }

    g_ptr_array_unref (modules);
    g_object_unref (resolver);
}

void
frida_gadget_environment_ensure_debugger_breakpoints_only (void)
{
    task_set_exception_ports (
        mach_task_self (),
        EXC_MASK_ALL & ~EXC_MASK_BREAKPOINT,
        MACH_PORT_NULL,
        EXCEPTION_DEFAULT,
        THREAD_STATE_NONE
    );
}
