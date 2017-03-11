# exc_handler
linux exc signal handler
这是个linux下处理异常信号的例子，比如常见的段错误，出现时对齐进行堆栈打印，回溯调用链（backytace），可以的话可以采取堆栈内容进行栈回溯。
gcc baktrace.c -g -rdynamic -o test
