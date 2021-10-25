#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <list>
#include <time.h>
#include <sys/time.h>




#define LOCALUDPFILE "/home/localallocudpfile.bin"
#define BUFFER_SIZE 200
#define STACKCOUNT 20


#pragma pack (1)
struct UDPPacket
{
	unsigned int mask;// 掩码
	unsigned char type;// 类型
	long long int pointaddr;// 指针地址
	unsigned int size;// 分配的大小
	unsigned char stackcount;// 分配对战大小
	long long int stack[STACKCOUNT];// 分配堆栈
}packet;
#pragma pack ()


struct tmpTransPacket
{
	bool type = false;
	long long int addr = 0;
	long long int time = 0;
	UDPPacket* packet = nullptr;
};

struct tmpMallocPacket
{
	long long int time = 0;
	long long int index = 0;
	UDPPacket* packet = nullptr;
};

int g_udpthreadloop = 1;
int g_udpsocket = -1;
std::mutex g_translistlock;
int g_translistcount = 0;
std::list<tmpTransPacket> g_translist;
std::unordered_map<long long int, tmpMallocPacket> g_malloclist;

long long int g_index = 0;
long long int g_startmonitortime = 0;
long long int g_endmonitortime = 0;

static long long int getsystemtime()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

void Log(const char* msg)
{
	time_t t = time(NULL);
	tm timeTm;
	localtime_r(&t, &timeTm);

	FILE* pfile = fopen("./log.txt", "a+");

	char timeinfo[256] = "";
	sprintf(timeinfo, "%04d-%02d-%02d-%02d:%02d:%02d", timeTm.tm_year + 1900, timeTm.tm_mon + 1, timeTm.tm_mday, timeTm.tm_hour, timeTm.tm_min, timeTm.tm_sec);	
	char buffer[4096] = "";
	sprintf(buffer, "%s: %s\n", timeinfo, msg);
	fwrite(buffer, 1, strlen(buffer), pfile);
	fclose(pfile);
	
	printf("%s", buffer);
}

extern void OnUDPThread();
int main()
{
	extern void RegisterSystemSignalHandler();
	RegisterSystemSignalHandler();

	Log("start create local udp socket");
	g_udpsocket = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (g_udpsocket < 0)
	{
		Log("local udp socket create failed");
		return 0;
	}
	Log("create local udp socket succeed");

	unlink(LOCALUDPFILE);
	Log("start bind local udp socket");
	struct sockaddr_un servaddr;
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strcpy(servaddr.sun_path, LOCALUDPFILE);
	if (bind(g_udpsocket, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		Log("local udp bind failed");
		return 0;
	}
	Log("bind local udp socket succeed");

	Log("start create local udp socket thread");
	std::thread udpthread(OnUDPThread);
	udpthread.detach();
	Log("create local udp socket thread succeed");

	while (true)
	{
		for (int i=0; i<1000; i++)
		{
			bool has = false;
			tmpTransPacket pack;
			g_translistlock.lock();
			if (g_translistcount > 0)
			{
				g_translistcount--;
				pack = g_translist.front();
				g_translist.pop_front();
				has = true;
			}
			g_translistlock.unlock();

			if (!has)
				break;

			// 插入
			if (pack.type)
			{// malloc
				if (g_malloclist.find(pack.addr) != g_malloclist.end())
				{
					//printf("has malloc: %lld\n", pack.addr);
				}

				if (g_startmonitortime!=0 && g_endmonitortime==0)
				{
					tmpMallocPacket tmpPack;
					tmpPack.time = pack.time;
					tmpPack.index = g_index;
					tmpPack.packet = pack.packet;
					g_malloclist[pack.addr] = tmpPack;

					g_index++;
				}
				else
				{
					delete pack.packet;
				}
			}
			else
			{// delete
				auto iter = g_malloclist.find(pack.addr);
				if (iter == g_malloclist.end())
				{
					//printf("has delete: %lld\n", pack.addr);
				}
				else
				{
					delete iter->second.packet;
					g_malloclist.erase(pack.addr);
				}
			}
		}

		// 判断有无CMD指令
		if (remove("quit.cmd") != -1)
		{// 退出
			Log("quit.cmd");
			g_udpthreadloop = 0;
			break;
		}

		if (remove("start.cmd") != -1)
		{// 开始监听
			Log("start.cmd");
			g_startmonitortime = getsystemtime();
		}

		if (remove("report.cmd") != -1)
		{// 打印监听
			if (g_endmonitortime == 0)
			{
				g_endmonitortime = getsystemtime();
			}
			Log("report.cmd");

			// 打印信息
			time_t t = time(NULL);
			tm timeTm;
			localtime_r(&t, &timeTm);
			char filename[128] = "";
			sprintf(filename, "./report-%04d-%02d-%02d-%02d:%02d:%02d.txt", timeTm.tm_year + 1900, timeTm.tm_mon + 1, timeTm.tm_mday, timeTm.tm_hour, timeTm.tm_min, timeTm.tm_sec);
			FILE* pfile = fopen(filename, "a+");
			// header
			{
				char buffer[1024] = "index	time	addr	size	stackcount	stacklist\n";
				fwrite(buffer, 1, strlen(buffer), pfile);
			}
			// body
			for (auto iter= g_malloclist.begin(); iter!= g_malloclist.end(); ++iter)
			{
				char stackinfo[1024] = "";
				for (int i=0; i<iter->second.packet->stackcount; i++)
				{
					sprintf(stackinfo, "%s%d:0x%llx ", stackinfo, i, iter->second.packet->stack[i]);
				}
				char buffer[1024] = "";
				sprintf(buffer, "%lld	%lld	0x%llx	%d	%d	%s\n", iter->second.index, iter->second.time, iter->first, iter->second.packet->size, iter->second.packet->stackcount, stackinfo);

				fwrite(buffer, 1, strlen(buffer), pfile);
			}
			fclose(pfile);
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	Log("end");
	return 0;
}

void OnUDPThread()
{
	char buf[BUFFER_SIZE] = "";
	struct sockaddr_un client_addr;
	socklen_t client_len = sizeof(client_addr);

	Log("OnUDPThread start");
	while (g_udpthreadloop)
	{
		bzero(buf, sizeof(buf));
		if (recvfrom(g_udpsocket, buf, BUFFER_SIZE, 0, (struct sockaddr*)&client_addr, &client_len) == 0)
		{
			Log("client udp recvfrom error");
			break;
		}

		int mask = *((int*)buf);
		if (mask != 78543505)
			continue;

		char* buf2 = (buf + 4);
		unsigned char type = buf2[0];
		if (type == 101 || type == 102 || type == 103)
		{// malloc
			buf2 = (buf2 + 1);
			long long int addr = *((long long int*)buf2);

			UDPPacket* pUDPPacket = new UDPPacket();
			memcpy(pUDPPacket, buf, sizeof(UDPPacket));
			
			tmpTransPacket pack;
			pack.type = true;
			pack.addr = addr;
			pack.time = getsystemtime();
			pack.packet = pUDPPacket;

			g_translistlock.lock();
			g_translist.push_back(pack);
			g_translistcount++;
			g_translistlock.unlock();
		}
		else if (type == 104 || type == 105)
		{// free
			buf2 = (buf2 + 1);
			long long int addr = *((long long int*)buf2);

			tmpTransPacket pack;
			pack.type = false;
			pack.addr = addr;

			g_translistlock.lock();
			g_translist.push_back(pack);
			g_translistcount++;
			g_translistlock.unlock();
		}
	}
	Log("OnUDPThread end");
}
