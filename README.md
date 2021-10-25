# LINUX下MALLOC-HOOK的一种方式，通过LD_PRELOAD实现底层内存分配与释放的统计，可用于定位内存泄漏等场景
### 1:mallocpreload：编译出对应的.so库，在目标程序启动时使用LD_PRELOAD="./libmalloc_preload.so" ./Test &运行；最好可以在应用程序内动态开启和关闭监控
### 2:mallocpreload_localudpserver：编译后为本地启动的malloc/new监控程序，会负责写入文件，然后通过EXCEL打开排序过滤选择，具体格式可参考代码
#### 注意1：目标进程GCC设置编译选项-fno-omit-frame-pointer，子进程继承时LD_PRELOAD的问题
#### 注意2：为了确保开发简单且监控数据不会丢失，必须采用Domain UDP Socket模式，才能确保不会丢包
