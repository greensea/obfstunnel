#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


#define OT_LOG(LEVEL, __fmt, ...)	if (LEVEL <= otcfg_log_level) fprintf(stderr, __fmt, ##__VA_ARGS__)
#define OT_LOGE(__fmt, ...)	OT_LOG(OT_LOGLEVEL_ERROR, __fmt, ##__VA_ARGS__)
#define OT_LOGW(__fmt, ...)	OT_LOG(OT_LOGLEVEL_WARNING, __fmt, ##__VA_ARGS__)
#define OT_LOGD(__fmt, ...)	OT_LOG(OT_LOGLEVEL_DEBUG, __fmt, ##__VA_ARGS__)
#define OT_LOGI(__fmt, ...)	OT_LOG(OT_LOGLEVEL_INFO, __fmt, ##__VA_ARGS__)

#define OT_LOGLEVEL_DEBUG	7
#define OT_LOGLEVEL_INFO	6
#define OT_LOGLEVEL_WARNING	5
#define OT_LOGLEVEL_ERROR	4

#define OT_SIDE_SERVER	1
#define OT_SIDE_CLIENT	2
#define OT_DEFAULT_PORT	1234
#define OT_PACKET_SIZE	18000	/// Max packet size for obfstunnel packet

extern int otcfg_log_level;
