# EPT-Hook-Examples
Examples of EPT hooking and tracing execution via mmr using the amazing [hv](https://github.com/jonomango/hv) hypervisor project  

Project "um" features usermode code for signalling installation of ept hooks and using hypercalls, cross-process ept hook (page in process A replaced with page from process B) was shown to be working -> replacing call to MessageBoxA() with ucrbase.puts() using dynamic lookups. "helpers.hpp" contains useful dynamic lookup functions such as module base retrieval and custom "GetProcAddress" (without using any WINAPIs).

Since we are cross-process EPT Hooking, VAs for APIs will be different and thus we must look up all info dynamically. All functions should all be inlined with stack security options turned off.  

Example of using mmr's for tracing execution of specific function in process:  
<img width="1255" height="534" alt="image" src="https://github.com/user-attachments/assets/ec160d92-9ffa-49e2-b5fe-b1ad9ec6f402" />  
