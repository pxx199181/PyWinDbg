//add code
#include "RemoteDBG.h"
#include "../bridge/bridgemain.h"
#include <thread>
#include <stdio.h>
#include <vector>

bool readfile(char *filename, char *&data) {
	data = 0;
	FILE *fp = fopen(filename, "rb");
	if (fp != NULL) {
		fseek(fp, 0, SEEK_END);
		long int size = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		data = (char *)calloc(1, size + 1);
		if (data == 0) {
			fclose(fp);
			return false;
		}
		fread(data, 1, size, fp);
		fclose(fp);
	}
	else
		return false;
	return true;
}

void logInfo(char *msg) {
	GuiAddLogMessage(msg);
	//printf(msg);
}

bool RecvTCP(SOCKET s, char *data, int size) {

	int sz_rd = 0;
	while (sz_rd < size) {
		int real_sz = recv(s, &data[sz_rd], size - sz_rd, 0);
		if (real_sz <= 0) {
			//syslog("bad recv");
			//isAlive = false;
			return false;
		}
		sz_rd += real_sz;
	}
	return true;
}

bool SendTCP(SOCKET s, char *data, int size) {

	int sz_sd = 0;
	while (sz_sd < size) {
		int real_sz = send(s, &data[sz_sd], size - sz_sd, 0);
		if (real_sz <= 0){
			//syslog("bad send");
			//isAlive = false;
			return false;
		}
		sz_sd += real_sz;
	}
	return true;
}

bool RecvSignPkt(SOCKET s, char &sign, char **data, int &size) {
	*data = 0;
	size = 0;

	if (RecvTCP(s, (char *)&sign, 1) == false) {
		return false;
	}

	if (RecvTCP(s, (char *)&size, 4) == false) {
		return false;
	}
	
	if (size > 0) {
		*data = (char *)malloc(size);
		if (*data == 0) {
			return false;
		}
		if (RecvTCP(s, *data, size) == false) {
			free(*data);
			return false;
		}
	}
	
	return true;
}

bool SendSignPkt(SOCKET s, char sign, char *data, int size) {
	if (SendTCP(s, (char *)&sign, 1) == false) {
		return false;
	}
	if (SendTCP(s, (char *)&size, 4) == false) {
		return false;
	}
	if (size > 0) {
		if (SendTCP(s, data, size) == false) {
			return false;
		}
	}
	return true;
}

typedef enum _RDBG_OP {
	RDBG_QUIT,
	RDBG_KILL,
	RDBG_READ,
	RDBG_WRITE,
	RDBG_CMD,

	RDBG_SMSG,

	RDBG_OK,
	RDBG_ERROR,

	RDBG_ISRUNING,
	RDBG_EVAL,
	RDBG_VALTOSTR,
	RDBG_REG_W,
	RDBG_REG_R,

	RDBG_DISASM,
	RDBG_ASM,
	
	RDBG_MODULEBASE,

	RDBG_WAITPAUSE,
	RDBG_CMD_DIRECT,

}REMOTE_DBG;

bool SendBackError(SOCKET sk, char *info = "error") {
	return SendSignPkt(sk, (char)RDBG_ERROR, info, strlen(info));
}

bool SendBackOk(SOCKET sk, char *info = "ok") {
	return SendSignPkt(sk, (char)RDBG_OK, info, strlen(info));
}

bool SendBackData(SOCKET sk, char *data, int size) {
	return SendSignPkt(sk, (char)RDBG_OK, data, size);
}

bool rdbg_read_mem(SOCKET sk, char *data, int total_size) {
	duint va;
	int size;
	va = *(duint*)data;
	size = *(int*)(data + sizeof(duint));
	char *dest = (char *)malloc(size);
	if (dest == 0)  {
		return SendBackError(sk, "error");
	}
	DbgMemRead(va, dest, size);
	bool result = SendBackData(sk, dest, size);
	free(dest);
	return result;
}

bool rdbg_write_mem(SOCKET sk, char *data, int total_size) {
	duint va;
	int size = total_size;
	va = *(duint*)data;
	char *dest = (data + sizeof(duint));
	DbgMemWrite(va, dest, size - sizeof(duint));
	return SendBackOk(sk, "ok");
}

bool rdbg_eval(SOCKET sk, char *data, int total_size) {
	bool success = false;
	duint value = DbgEval(data, &success);
	char *dest = (char *)&value;
	return SendBackData(sk, dest, sizeof(duint));
}

bool rdbg_valToString(SOCKET sk, char *data, int total_size) {
	duint value = *(duint*)data;
	char *dest = (data + sizeof(duint));
	DbgValToString(dest, value);
	return SendBackOk(sk, "ok");
}

bool rdbg_set_reg(SOCKET sk, char *data, int total_size) {
	return rdbg_valToString(sk, data, total_size);
}

bool rdbg_get_reg(SOCKET sk, char *data, int total_size) {
	return rdbg_eval(sk, data, total_size);
}

bool rdbg_disasm(SOCKET sk, char *data, int total_size) {
	duint va = *(duint*)data;
	char *dest = (data + sizeof(duint));
	DISASM_INSTR instr;
	DbgDisasmAt(va, &instr);
	return SendBackData(sk, (char *)&instr, sizeof(DISASM_INSTR));
}

bool rdbg_asm(SOCKET sk, char *data, int total_size) {
	duint va = *(duint*)data;
	char *dest = (data + sizeof(duint));
	bool res = DbgAssembleAt(va, dest);
	return SendBackData(sk, (char *)&res, 1);
}

bool rdbg_moduleBase(SOCKET sk, char *data, int total_size) {
	char *dest = data;
	duint base = DbgModBaseFromName(dest);
	dest = (char *)&base;
	return SendBackData(sk, dest, sizeof(duint));
}

bool rdbg_waitPause(SOCKET sk, char *data, int total_size) {
	while (DbgIsRunning()) {
		Sleep(500);
	}
	return SendBackOk(sk, "ok");
}

bool rdbg_isRunning(SOCKET sk, char *data, int total_size) {
	bool sign = DbgIsRunning();
	char *dest = (char *)&sign;
	return SendBackData(sk, dest, sizeof(char));
}

bool rdbg_cmd(SOCKET sk, char *data, int total_size) {
	//logInfo(data);
	int res = DbgCmdExec(data);
	return SendBackData(sk, (char *)&res, 1);
}


bool rdbg_cmd_direct(SOCKET sk, char *data, int total_size) {
	//logInfo(data);
	int res = DbgCmdExecDirect(data);
	return SendBackData(sk, (char *)&res, 1);
}

bool rdbg_smsg(SOCKET sk, char *data, int total_size) {
	duint va;
	char msgType = data[0]; 
	logInfo(data);
	return SendBackOk(sk, "ok");
}

bool debug_work(SOCKET sock) {
	char logbuff[0x100];
	bool debug_sign = true;
	bool work_sign = true;
	while (work_sign) {
		char opcode;
		char *data = 0;
		int size = 0;
		bool r_pkt_sign = RecvSignPkt(sock, opcode, &data, size);
		sprintf(logbuff, "opcode: %d, size: %d, sign: %d", opcode, size, r_pkt_sign);
		if (r_pkt_sign == false)
			return debug_sign;
		switch (opcode) {
		case RDBG_QUIT:
			debug_sign = false;
			break;
		case RDBG_READ:
			work_sign = rdbg_read_mem(sock, data, size);
			break;
		case RDBG_WRITE:
			work_sign = rdbg_write_mem(sock, data, size);
			break;
		case RDBG_SMSG:
			work_sign = rdbg_smsg(sock, data, size);
			break;
		case RDBG_CMD:
			work_sign = rdbg_cmd(sock, data, size);
			break;
		case RDBG_CMD_DIRECT:
			work_sign = rdbg_cmd_direct(sock, data, size);
			break;
		case RDBG_ISRUNING:
			work_sign = rdbg_isRunning(sock, data, size);
			break;
		case RDBG_EVAL:
			work_sign = rdbg_eval(sock, data, size);
			break;
		case RDBG_VALTOSTR:
			work_sign = rdbg_valToString(sock, data, size);
			break;
		case RDBG_REG_R:
			work_sign = rdbg_get_reg(sock, data, size);
			break;
		case RDBG_REG_W:
			work_sign = rdbg_set_reg(sock, data, size);
			break;
		case RDBG_DISASM:
			work_sign = rdbg_disasm(sock, data, size);
			break;
		case RDBG_ASM:
			work_sign = rdbg_asm(sock, data, size);
			break;
		case RDBG_MODULEBASE:
			work_sign = rdbg_moduleBase(sock, data, size);
			break;
		case RDBG_WAITPAUSE:
			work_sign = rdbg_waitPause(sock, data, size);
			break;
		default:
			break;
		}

		if(data)
			free(data);
	}
	return debug_sign;
}

char rdbg_ip[0x40] = { "0.0.0.0" };
int rdbg_port = 8888;
bool rdbg_use = FALSE;

SOCKET create_socket(char *ip, int port) {
	WSADATA wsa;
	struct sockaddr_in server;
	SOCKET s;

	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return -1;
	}

	printf("Initialised.\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
		return -1;
	}

	int nReuseAddr = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&nReuseAddr, sizeof(int));

	printf("Socket created.\n");

	//Prepare the sockaddr_in structure
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_port = htons(port);

	//Bind
	if (bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d", WSAGetLastError());
		return -1;
	}

	printf("Bind done");

	//Listen to incoming connections
	if (listen(s, 3) != 0)
	{
		printf("listen is error");
		return -1;
	}
	return s;
}

void RemoteDBG_Main() {
	SOCKET s = create_socket(rdbg_ip, rdbg_port);
	if (s == -1) {
		MessageBoxW(0, L"socket error", L"Tips", 0);
		return;
	}
	while (true) {
		struct sockaddr_in client;
		SOCKET conn_fd;
		int c;

		//Accept and incoming connection
		printf("Waiting for incoming connections...");

		c = sizeof(struct sockaddr_in);
		memset(&client, 0, sizeof(client));
		conn_fd = accept(s, (struct sockaddr *)&client, &c);
		if (conn_fd == INVALID_SOCKET)
		{
			logInfo("accept failed with error code");// , WSAGetLastError());
		}
		//int netTimeout = 30000; //30 second
		//setsockopt(conn_fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&netTimeout, sizeof(int));
		//setsockopt(conn_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&netTimeout, sizeof(int));

		logInfo("new debugger accepted\n");

		bool res = debug_work(conn_fd);
		closesocket(conn_fd);

		logInfo("debugger disconnect\n");

		if (res == false)
			break;
	}
	WSACleanup();
}

std::thread *gloabl_thread;

std::string StripStr(std::string data, char ch = -1) {
	int pos_b = 0;
	int pos_e = data.size() - 1;
	while (pos_b <= pos_e) {
		if (ch != -1) {
			if (data[pos_b] == ch)
				pos_b++;
			else
				break;
		}
		else {
			if (data[pos_b] == ' ' || data[pos_b] == '\t' || data[pos_b] == '\n' || data[pos_b] == '\r')
				pos_b++;
			else
				break;
		}


	}
	while (pos_e >= pos_b) {

		if (ch != -1) {
			if (data[pos_e] == ch)
				pos_e--;
			else
				break;
		}
		else {
			if (data[pos_e] == ' ' || data[pos_e] == '\t' || data[pos_e] == '\n' || data[pos_e] == '\r')
				pos_e--;
			else
				break;
		}
	}
	return data.substr(pos_b, pos_e - pos_b + 1);
}

std::vector<std::string> SplitStr(std::string data, char ch) {
	int pos_b = 0;
	int pos_e = 0;
	std::vector<std::string> strArray;
	std::string info;
	while (true) {
		pos_e = data.find(ch, pos_b);
		if (pos_e == -1) {
			info = data.substr(pos_b, data.size() - pos_b);
			info = StripStr(info);
			strArray.push_back(info);
			break;
		}
		info = data.substr(pos_b, pos_e - pos_b);
		info = StripStr(info);
		strArray.push_back(info);
		pos_b = pos_e + 1;
	}
	return strArray;
}
void RemoteDBG_Init() {
	//MessageBoxW(0, L"RemoteDBG_Init", L"tips", 0);
	strcpy(rdbg_ip, "0.0.0.0");
	rdbg_port = 8888;
	rdbg_use = FALSE;
	char confPath[MAX_PATH];
	GetModuleFileNameA(NULL, confPath, MAX_PATH);
	char *keyPtr = strrchr(confPath, '\\');
	if (keyPtr) {
		*keyPtr = 0;
	}
	strcat(confPath, "\\rdbg.conf");
	char *data = 0;
	if (readfile(confPath, data) == true) {
		std::vector<std::string> confArray = SplitStr(std::string(data), '\n');
		int i;
		for (i = 0; i < confArray.size(); i++) {
			if (confArray[i][0] == ';' || confArray[i][0] == '#')
				continue;

			std::vector<std::string> confItems = SplitStr(confArray[i], '=');
			if (confItems.size() != 2)
				continue;
			if (strcmpi(confItems[0].c_str(), "ip") == 0) {
				std::string ip = confItems[1];
				ip = StripStr(confItems[1], '\"');
				ip = StripStr(confItems[1], '\'');
				strcpy(rdbg_ip, confItems[1].c_str());
			}
			else if (strcmpi(confItems[0].c_str(), "port") == 0) {
				rdbg_port = atoi(confItems[1].c_str());
			}
			else if (strcmpi(confItems[0].c_str(), "use") == 0) {
				rdbg_use = atoi(confItems[1].c_str());
			}
		}
		free(data);
	}
	if (rdbg_use == true) {
		gloabl_thread = new std::thread(RemoteDBG_Main);
		//MessageBoxW(0, L"RemoteDBG_Init over", L"tips", 0);
	}
}


void RemoteDBG_Release() {
	//gloabl_thread->join();
	if (rdbg_use == true) {
		gloabl_thread->detach();
		delete gloabl_thread;
	}
}