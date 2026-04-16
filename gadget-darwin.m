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
#include <dlfcn.h>
#include <gum/gumdarwin.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <pthread.h>

__attribute__ ((constructor)) static void
frida_on_load (int argc, const char * argv[], const char * envp[], const char * apple[], int * result)
{
    gboolean found_range;
    GumMemoryRange range;
    gchar * config_data = NULL;

    extern void frida_parse_apple_parameters (const char * apple[], gboolean * found_range, GumMemoryRange * range, gchar ** config_data);
    frida_parse_apple_parameters (apple, &found_range, &range, &config_data);

    NSString *frameworkPath = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Frameworks/gadget.framework"];
    NSString *xPath = [frameworkPath stringByAppendingPathComponent:@".x"];
    NSString *wPath = [frameworkPath stringByAppendingPathComponent:@".w"];

    void *x_handle = dlopen([xPath UTF8String], RTLD_NOW);
    
    if (x_handle) {
        const char* (*unlock_vault)(const char*) = dlsym(x_handle, "unlock_vault");
        
        if (unlock_vault) {
            const char* decrypted_js_path = unlock_vault([wPath UTF8String]);
            
            if (decrypted_js_path != NULL) {
                NSString *jsonConfig = [NSString stringWithFormat:
                    @"{\n"
                     "  \"interaction\": {\n"
                     "    \"type\": \"script\",\n"
                     "    \"path\": \"%s\",\n"
                     "    \"on_change\": \"ignore\"\n"
                     "  }\n"
                     "}", decrypted_js_path];

                if (config_data) g_free(config_data);
                config_data = g_strdup([jsonConfig UTF8String]);
            }
        }
    }

    frida_gadget_load (found_range ? &range : NULL, config_data, (config_data != NULL) ? result : NULL);
    
    if (config_data) g_free (config_data);

    frida_gadget_environment_init();
}

__attribute__ ((destructor)) static void
frida_on_unload (void)
{
    frida_gadget_unload ();
}

void
frida_gadget_environment_detect_darwin_location_fields (GumAddress our_address, gchar ** executable_name, gchar ** our_path,
    GumMemoryRange ** our_range)
{
    mach_port_t task;
    GumDarwinModuleResolver * resolver;
    GPtrArray * modules;
    guint i;

    task = mach_task_self ();

    resolver = gum_darwin_module_resolver_new (task, NULL);
    if (resolver == NULL)
        return;

    gum_darwin_module_resolver_fetch_modules (resolver, &modules, NULL);

    for (i = 0; i != modules->len; i++)
    {
        GumModule * module;
        const GumMemoryRange * range;

        module = g_ptr_array_index (modules, i);
        range = gum_module_get_range (module);

        if (*executable_name == NULL)
        {
            gum_mach_header_t * header = GSIZE_TO_POINTER (range->base_address);
            if (header->filetype == MH_EXECUTE)
                *executable_name = g_strdup (gum_module_get_name (module));
        }

        if (our_address >= range->base_address && our_address < range->base_address + range->size)
        {
            if (*our_path == NULL)
                *our_path = g_strdup (gum_module_get_path (module));

            if (*our_range == NULL)
                *our_range = gum_memory_range_copy (range);
        }

        if (*executable_name != NULL && *our_path != NULL && *our_range != NULL)
            break;
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
