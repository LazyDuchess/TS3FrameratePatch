#include <Windows.h>
#include <stdint.h> 

bool init_D3D(); // if D3D found returns true
void wndProcHook(LPCSTR lpWindowName, LONG_PTR WndProc, WNDPROC oWndProc);
void wndProcUnhook(WNDPROC oWndProc);
void methodesHook(int index, LPVOID hkFunc, LPVOID* oFunc);
void methodesUnhook();


int return_D3D();
HWND return_Hwnd();
#if (_WIN64)
uint64_t* return_table();
#else
uint32_t* return_table();
#endif