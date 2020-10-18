# LoadLibrary Injector
**Classic LoadLibrary Injector**  
The purpose of this project was to understand and create an executable that enables the user to inject a dll into an externally running process.  
  
**What I've Learned:**  
  I got to understand the basic overview of .exe and .dll structures
  I learned various WINAPIs that specialize in memory or process management tasks.  
  
**Contents:**  
 - Utilizes Windows's External Memory API's (WriteProcessMemory, ReadProcessMemory, VirtualAllocEx)  
 - Additional Window's API Include (CreateToolhelp32Snapshot, OpenHandle, CreateRemoteThread, GetProcAddress)  
