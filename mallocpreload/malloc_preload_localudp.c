// Simple Mem Leak Check Code
// By LiCheng
// QQ:282948182
// mail:282948182@qq.com


#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <signal.h> 
#include <time.h>
#include <execinfo.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>


#define UDPMASK 78543505
#define IP "127.0.0.1"
#define PORT 9988
#define IP2 "127.0.0.1"
#define PORT2 9988
#define STACKCOUNT 20
#define LOCALUDPFILENAME "/home/localallocudpfile.bin"


// 暴露给外部的全局变量
#if 0
static int g_preLoadmalloclogflag = 1;// 都是记录日志开关
static int g_preloadmalloclogminsize = 1;// 记录分配的最小字节数-小于该数字则不需要记录
static int g_preloadmalloclogmaxsize = 10000000;// 记录分配的最大字节数-大于该数据则不需要记录
static long long int g_preloadmallocaddrlow = 0;// 记录分配的内存区间段-最低内存区间（0表示不用设置）
static long long int g_preloadmallocaddrhigh = 0;// 记录分配的内存区间段-最高内存区间（0表示不用设置）
#else
// 这部分其实没必要用extern，根据LINUX下面动态库的强弱符号覆盖规则，哪怕执行文件里面也定义了，但全局也只能有一份，访问的也都是一样的
extern int g_preLoadmalloclogflag;// 都是记录日志开关
extern int g_preloadmalloclogminsize;// 记录分配的最小字节数-小于该数字则不需要记录
extern int g_preloadmalloclogmaxsize;// 记录分配的最大字节数-大于该数据则不需要记录
extern long long int g_preloadmallocaddrlow;// 记录分配的内存区间段-最低内存区间（0表示不用设置）
extern long long int g_preloadmallocaddrhigh;// 记录分配的内存区间段-最高内存区间（0表示不用设置）
#endif



// 本地全局变量
static int g_mallochookinited = 0;
static int g_udpsocket = -1;
static void* (*g_malloc_real)(size_t) = NULL;
static void* (*g_calloc_real)(size_t,size_t) = NULL;
static void* (*g_realloc_real)(void*, size_t) = NULL;
//static void* (*g_memalign_real)(size_t, size_t) = NULL;
//static void* (*g_valloc_real)(size_t) = NULL;
static void (*g_free_real)(void*) = NULL;



// UDP消息包type定义
// 101:malloc
// 102:calloc
// 103:realloc
// 104:free
// 105:realloc-free


#define STACKCALL __attribute__((regparm(1),noinline))
static void** STACKCALL getEBP(void) {
	void** ebp = NULL;
	__asm__ __volatile__("mov %%rbp, %0;\n\t"
		:"=m"(ebp)
		: 
		: "memory");
	return (void**)(*ebp);
}
static int my_backtrace(void** buffer, int size)
{
	int frame = 0;
	void** ebp;
	void** ret = NULL;
	unsigned long long func_frame_distance = 0;
	if (buffer != NULL && size > 0)
	{
		ebp = getEBP();
		func_frame_distance = (unsigned long long)(*ebp) - (unsigned long long)ebp;
		while (ebp && frame < size
			&& (func_frame_distance < (1ULL << 24))//assume function ebp more than 16M
			&& (func_frame_distance > 0))
		{
			ret = ebp + 1;
			buffer[frame++] = *ret;
			ebp = (void**)(*ebp);
			func_frame_distance = (unsigned long long)(*ebp) - (unsigned long long)ebp;
		}
	}
	return frame;
}

static long long int getsystemtime()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec*1000 + tv.tv_usec/1000);
}

static void  init_hooking()
{
	printf("start init_hooking\n");

	g_malloc_real = dlsym(RTLD_NEXT, "malloc");
	printf("g_malloc_real at %p\n", g_malloc_real);
	g_calloc_real = dlsym(RTLD_NEXT, "calloc");
	printf("g_calloc_real at %p\n", g_calloc_real);
	g_realloc_real = dlsym(RTLD_NEXT, "realloc");
	printf("g_realloc_real at %p\n", g_realloc_real);
	g_free_real = dlsym(RTLD_NEXT, "free");
	printf("g_free_real at %p\n", g_free_real);
	printf("init_hooking() call finish!!!\n");

	g_mallochookinited = 1;
	g_udpsocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	printf("create local udp=%d\n", g_udpsocket);
}


void* malloc(size_t size)
{
	//printf("malloc(size_t size=%d) call\n", size);
	if (g_malloc_real == NULL) 
		init_hooking();

	void* ret = g_malloc_real(size);
    //printf("malloc(size_t size=%d) call, ptr=%p\n", size, ret);
	if (g_preLoadmalloclogflag==1 && size>=g_preloadmalloclogminsize && size<=g_preloadmalloclogmaxsize)
	{
		if (g_preloadmallocaddrlow!=0 && (long long int)ret<g_preloadmallocaddrlow)
		{
			return ret;
		}
		if (g_preloadmallocaddrhigh!=0 && (long long int)ret>g_preloadmallocaddrhigh)
		{
			return ret;
		}

#pragma pack (1)
		struct UDPMallocPacket
		{
			unsigned int mask;// 掩码
			unsigned char type;// 类型
			long long int pointaddr;// 指针地址
			unsigned int size;// 分配的大小
			unsigned char stackcount;// 分配对战大小
			long long int stack[STACKCOUNT];// 分配堆栈
		}packet;
#pragma pack ()
		memset(&packet, 0, sizeof(packet));
		packet.mask = UDPMASK;
		packet.type = 101;
		packet.pointaddr = (long long int)(ret);
		packet.size = size;

		void* func[STACKCOUNT];
		packet.stackcount = (unsigned char)my_backtrace(func, STACKCOUNT);
		unsigned char i = 0;
		for (i = 0; i < packet.stackcount; i++)
		{
			packet.stack[i] = (long long int)func[i];
		}

		struct sockaddr_un addr;
		bzero(&addr, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strcpy(addr.sun_path, LOCALUDPFILENAME);
		sendto(g_udpsocket, &packet, sizeof(packet), 0, &addr, sizeof(addr));
	}

	return ret;
}


void* calloc(size_t num, size_t size)
{
	//printf("calloc(size_t num=%d, size_t size=%d) call\n", num, size);

	void* ret = NULL;
	if (g_mallochookinited == 0)
	{
		ret = sbrk(num*size);
        //printf("calloc(size_t num=%d, size_t size=%d) call sbrk, ptr=%p\n", num, size, ret);
	}
	else
	{
		ret = g_calloc_real(num,size);
		//ret = g_malloc_real(num*size);
        //memset((char*)ret, 0, num*size);
        //printf("calloc(size_t num=%d, size_t size=%d) call, ptr=%p\n", num, size, ret);

		if (g_preLoadmalloclogflag==1 && num*size>=g_preloadmalloclogminsize && num*size<=g_preloadmalloclogmaxsize)
		{
			if (g_preloadmallocaddrlow!=0 && (long long int)ret<g_preloadmallocaddrlow)
			{
				return ret;
			}
			if (g_preloadmallocaddrhigh!=0 && (long long int)ret>g_preloadmallocaddrhigh)
			{
				return ret;
			}

	#pragma pack (1)
			struct UDPMallocPacket
			{
				unsigned int mask;// 掩码
				unsigned char type;// 类型
				long long int pointaddr;// 指针地址
				unsigned int size;// 分配的大小
				unsigned char stackcount;// 分配对战大小
				long long int stack[STACKCOUNT];// 分配堆栈
			}packet;
	#pragma pack ()
			memset(&packet, 0, sizeof(packet));
			packet.mask = UDPMASK;
			packet.type = 102;
			packet.pointaddr = (long long int)(ret);
			packet.size = size;

			void* func[STACKCOUNT];
			packet.stackcount = (unsigned char)my_backtrace(func, STACKCOUNT);
			unsigned char i = 0;
			for (i = 0; i < packet.stackcount; i++)
			{
				packet.stack[i] = (long long int)func[i];
			}

			struct sockaddr_un addr;
			bzero(&addr, sizeof(addr));
			addr.sun_family = AF_LOCAL;
			strcpy(addr.sun_path, LOCALUDPFILENAME);
			sendto(g_udpsocket, &packet, sizeof(packet), 0, &addr, sizeof(addr));
		}
	}

	return ret;
}


void* realloc(void* ptr, size_t size)
{
	//printf("realloc(void* ptr, size_t size=%d) call\n", size);
	if (ptr!=NULL)
	{
		if (g_preLoadmalloclogflag == 1)
		{
#pragma pack (1)
			struct UDPFreePacket
			{
				unsigned int mask;// 掩码
				unsigned char type;// 类型
				long long int pointaddr;// 指针地址
			}packet;
#pragma pack ()
			memset(&packet, 0, sizeof(packet));
			packet.mask = UDPMASK;
			packet.type = 105;
			packet.pointaddr = (long long int)ptr;

			struct sockaddr_un addr;
			bzero(&addr, sizeof(addr));
			addr.sun_family = AF_LOCAL;
			strcpy(addr.sun_path, LOCALUDPFILENAME);
			sendto(g_udpsocket, &packet, sizeof(packet), 0, &addr, sizeof(addr));
		}
	}
	
	void* ret = g_realloc_real(ptr, size);
	//printf("realloc, size=%d, oldptr=%p, newptr=%p\n", size, ptr, ret);
	if (g_preLoadmalloclogflag==1 && size>=g_preloadmalloclogminsize && size<=g_preloadmalloclogmaxsize)
	{
		if (g_preloadmallocaddrlow!=0 && (long long int)ret<g_preloadmallocaddrlow)
		{
			return ret;
		}
		if (g_preloadmallocaddrhigh!=0 && (long long int)ret>g_preloadmallocaddrhigh)
		{
			return ret;
		}

#pragma pack (1)
		struct UDPMallocPacket
		{
			unsigned int mask;// 掩码
			unsigned char type;// 类型
			long long int pointaddr;// 指针地址
			unsigned int size;// 分配的大小
			unsigned char stackcount;// 分配对战大小
			long long int stack[STACKCOUNT];// 分配堆栈
		}packet;
#pragma pack ()
		memset(&packet, 0, sizeof(packet));
		packet.mask = UDPMASK;
		packet.type = 103;
		packet.pointaddr = (long long int)(ret);
		packet.size = size;

		void* func[STACKCOUNT];
		packet.stackcount = (unsigned char)my_backtrace(func, STACKCOUNT);
		unsigned char i = 0;
		for (i = 0; i < packet.stackcount; i++)
		{
			packet.stack[i] = (long long int)func[i];
		}

		struct sockaddr_un addr;
		bzero(&addr, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strcpy(addr.sun_path, LOCALUDPFILENAME);
		sendto(g_udpsocket, &packet, sizeof(packet), 0, &addr, sizeof(addr));
	}

	return ret;
}

void free(void* ptr)
{
	if (ptr == NULL)
		return;
	//printf("free call,ptr=%p\n", ptr);

	if (g_preLoadmalloclogflag == 1)
	{
		if (g_preloadmallocaddrlow!=0 && (long long int)ptr<g_preloadmallocaddrlow)
		{
			g_free_real(ptr);
			return;
		}
		if (g_preloadmallocaddrhigh!=0 && (long long int)ptr>g_preloadmallocaddrhigh)
		{
			g_free_real(ptr);
			return;
		}

#pragma pack (1)
		struct UDPFreePacket
		{
			unsigned int mask;// 掩码
			unsigned char type;// 类型
			long long int pointaddr;// 指针地址
		}packet;
#pragma pack ()
		memset(&packet, 0, sizeof(packet));
		packet.mask = UDPMASK;
		packet.type = 104;
		packet.pointaddr = (long long int)ptr;

		struct sockaddr_un addr;
		bzero(&addr, sizeof(addr));
		addr.sun_family = AF_LOCAL;
		strcpy(addr.sun_path, LOCALUDPFILENAME);
		sendto(g_udpsocket, &packet, sizeof(packet), 0, &addr, sizeof(addr));
	}

	g_free_real(ptr);
    //printf("free call end,ptr=%p\n", ptr);
}


