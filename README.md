# 过写拷贝全局Messagebox监视器
## 三环

1. 加载驱动
2. 通过 `DeviceIoControl` 让驱动设置调用门
3. 读取 `MessageBox` 所在的地址，让操作系统为其挂上物理页，防止 `PTE` 无效
4. 通过带参提权调用门调用 `setPTE` 函数，通过修改 `PTE` 和 `PDE` 的属性过写拷贝
5. 通过 `DeviceIoControl` 让驱动设置中断门
6. 把 `MessageBox` 前两个字节patch为 `0x20cd` ( `int 0x20` )
7. 通过 `DeviceIoControl` 不断从驱动获取函数调用记录并展示在终端
8. 卸载驱动，将 `MessageBox` 前两字节改回 `0xff8b` ( `mov edi, edi` )



## 零环

+ 设置调用门，偷懒了，直接硬编码写进去，

  ```c
  RtlMoveMemory(&t, pIoBuffer, uInLength);
  lo = t & 0x0000ffff;
  hi = t & 0xffff0000;
  *((PULONG)0x8003f048) = 0x00080000 | lo;
  *((PULONG)0x8003f04c) = 0x0000ec03 | hi;
  ```

+ 设置中断门，也是写死的硬编码

  ```c
  ULONG IntGateLo = (((ULONG)pFunc & 0x0000FFFF) | 0x00080000);
  ULONG IntGateHi = (((ULONG)pFunc & 0xFFFF0000) | 0x0000EE00);
  
  *((PULONG)0x8003f500) = IntGateLo;
  *((PULONG)0x8003f504) = IntGateHi;
  ```

  这里把中断处理函数设置为 `User32ApiSpyNaked` 。其获取三环EIP和ESP并调用一个内平栈的函数 `User32ApiSpy` 来从堆栈中读取出



## TODO

- [ ] 设置调用门时遍历GDT，找到空的表项填入
- [ ] 设置中断门时遍历IDT，找到空的表项填入
- [ ] 退出时应可以将GDT和IDT表中相应的表项改回原样
- [ ] 应能通过某种方法知道调用Messagebox的是哪个进程，然后不仅要能展示出调用的参数，还要展示出这个进程中对应的字符串。