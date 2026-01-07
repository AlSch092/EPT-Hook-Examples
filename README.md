# EPT-Hook-Examples
Examples of EPT hooking &amp; tracepoints using the [hv](https://github.com/jonomango/hv) hypervisor project  

Project "um" features usermode code for placing hooks and using hypercalls, cross-process was shown to be working -> replacing call to MessageBoxA() with ucrbase.puts() using dynamic lookups. "helpers.hpp" contains useful dynamic lookup functions such as module base retrieval and custom "GetProcAddress" (without using any WINAPIs).

Since we are cross-process EPT Hooking, VAs for APIs will be different and thus we must look up all info dynamically. All functions should all be inlined with stack security options turned off.


More info coming soon..  
