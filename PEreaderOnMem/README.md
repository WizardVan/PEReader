PEreaderOnMem rewrite a section in a loaded module on memory.It looks like a very classic way to erase or extract code or data in running time.But actually it can do more,for example,rewrite code part in running time and change whole program.Of course ,it is complicated when applied under a cache system or memory protection system.  

PEreaderOnMem 可以在运行中重写内存的代码部分，这个技术在大多数的木马中都有体现。当然修改代码时要注意绕过dep，还有当然是内存保护和刷新cache
