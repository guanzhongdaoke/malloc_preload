#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <chrono>
#include <thread>
#include <time.h>
#include <iostream>
#include <csignal>
#include <time.h>
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <signal.h> 
#include <time.h>
#include <execinfo.h>


static const char* s_pSigName[32] =
{
		NULL,
		"SIGHUP",
		"SIGINT",
		"SIGQUIT",
		"SIGILL",
		"SIGTRAP",
		"SIGABRT",
		"SIGBUS",
		"SIGFPE",
		"SIGKILL",
		"SIGUSR1",
		"SIGSEGV",
		"SIGUSR2",
		"SIGPIPE",
		"SIGALRM",
		"SIGTERM",
		"SIGSTKFLT",
		"SIGCHLD",
		"SIGCONT",
		"SIGSTOP",
		"SIGTSTP",
		"SIGTTIN",
		"SIGTTOU",
		"SIGURG",
		"SIGXCPU",
		"SIGXFSZ",
		"SIGVTALRM",
		"SIGPROF",
		"SIGWINCH",
		"SIGPOLL",
		"SIGPWR",
		"SIGSYS"
};

const char* _signal_name_(const int aSigNum)
{
	if ((0 < aSigNum) && (aSigNum < (int)sizeof(s_pSigName)))
	{
		return s_pSigName[aSigNum];
	}
	else
	{
		return "INVALID SIGNAL";
	}
}

static void _linux_signal_handler_(int signum)
{
	// Resume default behavior for the signal to exit without calling back signalHandler()
	// Raise it to get a core, with gdb pointing directly at the right thread, and also return the right exit code.
	signal(signum, SIG_DFL);
	raise(signum);
}

// 监听系统信号处理
// 主要是LINUX系统下的信号监听
void RegisterSystemSignalHandler()
{
	/* Set up the structure to specify the new action. */
	struct sigaction new_action;
	new_action.sa_handler = _linux_signal_handler_;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = SA_ONSTACK; // Use dedicated alternate signal stack

	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	//sigaction(SIGINT, &new_action, NULL); // 2
	//sigaction(SIGQUIT, &new_action, NULL); // 3
	//sigaction(SIGILL, &new_action, NULL); // 4
	//sigaction(SIGTRAP, &new_action, NULL); // 5
	//sigaction(SIGABRT, &new_action, NULL); // 6
	//sigaction(SIGFPE, &new_action, NULL); // 8
	//sigaction(SIGSEGV, &new_action, NULL); // 11
	//sigaction(SIGTERM, &new_action, NULL); // 15
}

